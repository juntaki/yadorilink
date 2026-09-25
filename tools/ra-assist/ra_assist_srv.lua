-- Loaded once into a persistent `nvim --headless --listen <socket>` process.
-- Defines the global RA_ASSIST table that ./ra-assist calls into via
-- `nvim --server <socket> --remote-expr`. Keeping the process alive means
-- vim.lsp.start()'s own dedup-by-config reuses the same rust-analyzer
-- instance (and its warm index) across every call instead of paying the
-- workspace-load cost on every invocation.
--
-- The whole command surface goes through M.dispatch(argv): the shell client
-- forwards its arguments untouched, and every bit of parsing, defaulting and
-- validation lives here rather than being written twice.

RA_ASSIST = RA_ASSIST or {}
local M = RA_ASSIST

local uv = vim.uv or vim.loop

-- `dofile` runs once, at daemon start, and the resulting functions live in
-- the daemon's Lua VM from then on -- so editing this file changes nothing
-- until the daemon restarts. That used to be a documented footgun ("run
-- `ra-assist stop` before testing a change, or you're talking to stale
-- code"), which is a rule that only works while someone remembers it. The
-- client compares this against the file's mtime on disk and restarts the
-- daemon itself when they differ, so there is nothing left to remember.
M.SRC_PATH = (debug.getinfo(1, "S").source or ""):gsub("^@", "")
M.SRC_MTIME = (function()
  local stat = M.SRC_PATH ~= "" and uv.fs_stat(M.SRC_PATH) or nil
  return stat and stat.mtime.sec or 0
end)()

-- The comparison happens here, not in the shell.
--
-- The client used to answer this with `stat -c %Y`, falling back to BSD's
-- `stat -f %m` -- two spellings of one syscall, neither of which is
-- guaranteed, and a third outcome ("neither worked") that silently means
-- "restart on every single call" and costs the full workspace load each
-- time. The daemon already has the file open to it through libuv, so let it
-- stat its own source: one implementation, no shell tool, nothing to detect.
function M.is_stale()
  if M.SRC_PATH == "" then
    return "0"
  end
  local stat = uv.fs_stat(M.SRC_PATH)
  if not stat then
    return "0"
  end
  return stat.mtime.sec ~= M.SRC_MTIME and "1" or "0"
end
local diff_text = (vim.text and vim.text.diff) or vim.diff

local DEFAULT_TIMEOUT_MS = 180000
local DEFAULT_LIMIT = 200

-- root_dir -> { client_id, active_progress, last_activity_ms, handler_installed }
local state_by_root = {}

-- Re-reads every buffer this daemon holds whose file has moved on disk.
--
-- The buffers outlive any one call, and the files under them keep
-- changing -- another tool's edit, a `git checkout`, a rebase. A stale
-- buffer is not merely out of date locally: nvim has already sent its
-- contents to rust-analyzer, so the server answers questions about the
-- file as it was, and a multi-file edit (a rename, above all) computes
-- positions from that stale text and applies them to the current file.
--
-- `checktime` reloads only buffers whose file changed and which have no
-- unsaved edits of their own, so this cannot discard anything: every
-- edit this daemon makes is written immediately.
local function resync_open_buffers()
  for _, bufnr in ipairs(vim.api.nvim_list_bufs()) do
    if
      vim.api.nvim_buf_is_loaded(bufnr)
      and not vim.bo[bufnr].modified
      and vim.api.nvim_buf_get_name(bufnr) ~= ""
    then
      vim.api.nvim_buf_call(bufnr, function()
        vim.cmd("silent! checktime")
      end)
    end
  end
end

local function open_buf(file)
  resync_open_buffers()
  local abspath = vim.fn.fnamemodify(file, ":p")
  if not uv.fs_stat(abspath) then
    error("no such file: " .. file)
  end
  local bufnr = vim.fn.bufnr(abspath)
  if bufnr == -1 then
    bufnr = vim.fn.bufadd(abspath)
    vim.fn.bufload(bufnr)
  else
    -- Buffers persist across calls in this daemon, but the file on disk
    -- can change between calls (a `git checkout --` after a rejected
    -- edit, another apply, a manual fix). Without forcing a resync here,
    -- the next :wall hits Vim's "file changed since reading it"
    -- confirmation, which nothing can answer in headless mode -- it hangs
    -- forever, wedging the whole daemon. on_reload (from the LSP buffer
    -- attach) re-syncs rust-analyzer's view when :edit! fires.
    vim.api.nvim_buf_call(bufnr, function()
      vim.cmd("edit!")
    end)
  end
  vim.bo[bufnr].filetype = "rust"
  return bufnr
end

-- vim.fs.root() stops at the *nearest* Cargo.toml, which in a cargo
-- workspace is the member crate's own manifest, not the workspace root.
-- Walk all ancestors and prefer the topmost one that declares [workspace],
-- so root_dir matches what a real `cargo metadata` run would consider the
-- workspace root.
local function root_for(bufnr)
  local name = vim.api.nvim_buf_get_name(bufnr)
  if name == "" then
    return vim.fn.getcwd()
  end
  local nearest_manifest_dir = nil
  local workspace_dir = nil
  for dir in vim.fs.parents(name) do
    local manifest = dir .. "/Cargo.toml"
    if uv.fs_stat(manifest) then
      nearest_manifest_dir = nearest_manifest_dir or dir
      local ok, lines = pcall(vim.fn.readfile, manifest)
      if ok and table.concat(lines, "\n"):find("%[workspace%]") then
        workspace_dir = dir
      end
    end
  end
  return workspace_dir or nearest_manifest_dir or vim.fn.getcwd()
end

-- Ensures a rust-analyzer client is running for `root`, attached to
-- `bufnr`, and that its workspace-load progress has gone quiet. Safe to
-- call on every request: cheap no-op checks once warm.
local function ensure_ready(bufnr, root, timeout_ms)
  local st = state_by_root[root]
  if not st then
    st = { active_progress = {}, last_activity_ms = uv.now() }
    state_by_root[root] = st
  end

  local client_id = vim.lsp.start({
    name = "rust-analyzer",
    cmd = { "rust-analyzer" },
    root_dir = root,
    on_init = function(client)
      if st.handler_installed then
        return
      end
      st.handler_installed = true
      client.handlers["$/progress"] = function(_, result)
        local value = result and result.value
        if not value then
          return
        end
        st.last_activity_ms = uv.now()
        if value.kind == "begin" then
          st.active_progress[result.token] = true
        elseif value.kind == "end" then
          st.active_progress[result.token] = nil
        end
      end
    end,
  }, { bufnr = bufnr })

  if not client_id then
    error("failed to start/attach rust-analyzer for root " .. root)
  end
  st.client_id = client_id

  local initialized = vim.wait(timeout_ms, function()
    local c = vim.lsp.get_clients({ id = client_id })[1]
    return c ~= nil and c.initialized == true
  end, 50)
  if not initialized then
    error("rust-analyzer did not initialize within " .. timeout_ms .. "ms")
  end

  -- Multiple progress phases (fetch metadata, then indexing, ...) can run
  -- back to back with small gaps, so "ready" means: nothing active right
  -- now, and nothing has started or ended for a full quiet window.
  --
  -- This window is not politeness, it is correctness for the read-side
  -- commands too: a `references` query answered mid-index comes back
  -- empty rather than failing, and an empty answer reads exactly like
  -- "this symbol is dead code". Every command below goes through here, so
  -- none of them can observe that state.
  local quiet_ms = 1500
  local ready = vim.wait(timeout_ms, function()
    if next(st.active_progress) ~= nil then
      return false
    end
    return (uv.now() - st.last_activity_ms) >= quiet_ms
  end, 100)
  if not ready then
    error("rust-analyzer workspace loading did not finish within " .. timeout_ms .. "ms")
  end

  return vim.lsp.get_clients({ id = client_id })[1]
end

local function request(client, bufnr, method, params, timeout_ms)
  local resp = client:request_sync(method, params, timeout_ms, bufnr)
  if not resp then
    error(method .. " timed out after " .. timeout_ms .. "ms")
  end
  if resp.err then
    error(method .. " failed: " .. vim.inspect(resp.err))
  end
  return resp.result
end

local function notify(client, method, params)
  client:notify(method, params)
end

-- ---------------------------------------------------------------------------
-- Output formatting
--
-- Everything prints as plain text lines, `path:line:col` first, because the
-- consumer is a coding agent reading through a terminal: that prefix is the
-- same shape `grep -n` and `cargo` emit, so it stays clickable and greppable,
-- and it is far cheaper than the JSON these answers arrive as.
-- ---------------------------------------------------------------------------

local function relpath(path, root)
  if root and path:sub(1, #root + 1) == root .. "/" then
    return path:sub(#root + 2)
  end
  return path
end

-- Reads one 0-based line of a file, preferring a loaded buffer (which may
-- hold edits newer than disk). Cached per command so N references into the
-- same file read it once.
local function line_reader()
  local cache = {}
  return function(path, lnum0)
    local lines = cache[path]
    if lines == nil then
      local bufnr = vim.fn.bufnr(path)
      if bufnr ~= -1 and vim.api.nvim_buf_is_loaded(bufnr) then
        lines = vim.api.nvim_buf_get_lines(bufnr, 0, -1, false)
      else
        local ok, read = pcall(vim.fn.readfile, path)
        lines = ok and read or {}
      end
      cache[path] = lines
    end
    return vim.trim(lines[lnum0 + 1] or "")
  end
end

-- A Location, a LocationLink and a DocumentSymbol all name a place but
-- spell it differently; normalise to uri + the range worth pointing at.
local function loc_parts(loc)
  if loc.targetUri then
    return loc.targetUri, loc.targetSelectionRange or loc.targetRange
  end
  if loc.location then
    return loc.location.uri, loc.location.range
  end
  return loc.uri, loc.selectionRange or loc.range
end

local function fmt_locations(locs, root, limit, label_of)
  local read_line = line_reader()
  local lines = {}
  local total = #locs
  for i, loc in ipairs(locs) do
    if i > limit then
      break
    end
    local uri, range = loc_parts(loc)
    if uri and range then
      local path = vim.uri_to_fname(uri)
      local label = label_of and label_of(loc) or read_line(path, range.start.line)
      table.insert(
        lines,
        string.format(
          "%s:%d:%d\t%s",
          relpath(path, root),
          range.start.line + 1,
          range.start.character + 1,
          label
        )
      )
    end
  end
  if total > limit then
    table.insert(lines, string.format("... %d more (use --limit=N to see them)", total - limit))
  end
  return table.concat(lines, "\n")
end

local SYMBOL_KIND = {
  [1] = "file", [2] = "module", [3] = "namespace", [4] = "package", [5] = "class",
  [6] = "method", [7] = "property", [8] = "field", [9] = "constructor", [10] = "enum",
  [11] = "interface", [12] = "function", [13] = "variable", [14] = "constant",
  [15] = "string", [16] = "number", [17] = "boolean", [18] = "array", [19] = "object",
  [20] = "key", [21] = "null", [22] = "enum-member", [23] = "struct", [24] = "event",
  [25] = "operator", [26] = "type-param",
}

local function kind_name(kind)
  return SYMBOL_KIND[kind] or ("kind" .. tostring(kind))
end

-- ---------------------------------------------------------------------------
-- Argument parsing
--
-- Positions accept both the original `<file> <line> <col>` triple and a
-- compact single token (`src/lib.rs:12:5`, `src/lib.rs:12-40`,
-- `src/lib.rs@some_fn`, `PeerSyncSession`). The symbol forms exist because
-- line/col go stale the moment an edit lands above them, and a refactor
-- aimed at a stale position does not fail -- it silently hits the wrong
-- code. Naming the symbol is re-resolved against the current tree on every
-- call, so it cannot go stale at all.
-- ---------------------------------------------------------------------------

local function is_number(s)
  return type(s) == "string" and s:match("^%d+$") ~= nil
end

local function parse_flags(argv)
  local flags, rest = {}, {}
  local positional_only = false
  for _, a in ipairs(argv) do
    if positional_only then
      table.insert(rest, a)
    elseif a == "--" then
      positional_only = true
    elseif a:sub(1, 2) == "--" then
      local k, v = a:match("^%-%-([%w%-]+)=(.*)$")
      if k then
        flags[k] = v
      else
        flags[a:sub(3)] = true
      end
    else
      table.insert(rest, a)
    end
  end
  return flags, rest
end

-- Consumes one location from `rest` starting at `i`; returns a spec plus the
-- next index. The spec is unresolved on purpose -- symbol forms need a live
-- client, which the caller only has after ensure_ready.
local function take_loc(rest, i)
  local first = rest[i]
  if first == nil then
    error("expected a position")
  end

  -- Legacy triple/quintuple: <file> <l> <c> [<l2> <c2>]
  if is_number(rest[i + 1]) and is_number(rest[i + 2]) then
    local spec = {
      file = first,
      l1 = tonumber(rest[i + 1]),
      c1 = tonumber(rest[i + 2]),
    }
    if is_number(rest[i + 3]) and is_number(rest[i + 4]) then
      spec.l2, spec.c2 = tonumber(rest[i + 3]), tonumber(rest[i + 4])
      return spec, i + 5
    end
    spec.l2, spec.c2 = spec.l1, spec.c1
    return spec, i + 3
  end

  -- file@Symbol / @Symbol / bare Symbol
  local file_part, sym = first:match("^(.*)@([%w_:]+)$")
  if sym then
    return { file = file_part ~= "" and file_part or nil, symbol = sym }, i + 1
  end

  -- file:l[:c][-l2[:c2]]
  local path, coords = first:match("^(.-):(%d[%d:%-]*)$")
  if path then
    local l1, c1, l2, c2 = coords:match("^(%d+):(%d+)%-(%d+):(%d+)$")
    if not l1 then
      local a, b = coords:match("^(%d+)%-(%d+)$")
      if a then
        -- A bare line range means whole lines. The end column is filled in
        -- from the buffer in resolve(), once there is one: ending at column
        -- 1 of the last line would clip it, and a made-up large column is
        -- not a position the server has to accept.
        return { file = path, l1 = tonumber(a), c1 = 1, l2 = tonumber(b), whole_lines = true }, i + 1
      end
    end
    if not l1 then
      local a, b = coords:match("^(%d+):(%d+)$")
      if a then
        l1, c1, l2, c2 = a, b, a, b
      end
    end
    if not l1 and coords:match("^%d+$") then
      l1, c1, l2, c2 = coords, "1", coords, "1"
    end
    if l1 then
      return {
        file = path,
        l1 = tonumber(l1),
        c1 = tonumber(c1),
        l2 = tonumber(l2),
        c2 = tonumber(c2),
      }, i + 1
    end
  end

  -- A path that exists on disk with no coordinates: whole-file commands.
  if uv.fs_stat(vim.fn.fnamemodify(first, ":p")) then
    return { file = first }, i + 1
  end

  -- Anything else is treated as a workspace symbol name.
  return { symbol = first }, i + 1
end

-- Picks a buffer to attach the client to when the caller named a symbol
-- rather than a file. Any tracked Rust file in the repo will do -- root_for
-- walks up to the workspace manifest from there regardless.
local function anchor_file()
  for _, bufnr in ipairs(vim.api.nvim_list_bufs()) do
    local name = vim.api.nvim_buf_get_name(bufnr)
    if name ~= "" and name:sub(-3) == ".rs" and uv.fs_stat(name) then
      return name
    end
  end
  local out = vim.fn.systemlist({ "git", "ls-files", "*.rs" })
  if vim.v.shell_error == 0 and out[1] then
    return out[1]
  end
  local found = vim.fs.find(function(name)
    return name:sub(-3) == ".rs"
  end, { path = vim.fn.getcwd(), type = "file", limit = 1 })
  if found[1] then
    return found[1]
  end
  error("no Rust file found to anchor the workspace; pass a file-qualified position")
end

-- Walks a DocumentSymbol tree collecting every symbol whose name, or whose
-- `Container::name` path, ends with the requested `::`-separated path.
local function match_doc_symbols(symbols, want, prefix, out)
  for _, s in ipairs(symbols or {}) do
    local path = prefix == "" and s.name or (prefix .. "::" .. s.name)
    if path == want or path:sub(-(#want + 2)) == "::" .. want or s.name == want then
      table.insert(out, { name = path, kind = s.kind, range = s.selectionRange or s.range })
    end
    match_doc_symbols(s.children, want, path, out)
  end
  return out
end

-- Resolves a spec to { bufnr, client, root, l1, c1, l2, c2 }. Symbol specs
-- go through documentSymbol (file-qualified) or workspace/symbol (bare), and
-- refuse to guess when more than one symbol matches.
local function resolve(spec, timeout_ms)
  local file = spec.file or (spec.symbol and anchor_file())
  local bufnr = open_buf(file)
  local root = root_for(bufnr)
  local client = ensure_ready(bufnr, root, timeout_ms)

  if not spec.symbol then
    local c2 = spec.c2 or spec.c1
    if spec.whole_lines then
      local last = vim.api.nvim_buf_get_lines(bufnr, spec.l2 - 1, spec.l2, false)[1] or ""
      c2 = #last + 1
    end
    return {
      bufnr = bufnr,
      client = client,
      root = root,
      file = vim.api.nvim_buf_get_name(bufnr),
      l1 = spec.l1,
      c1 = spec.c1,
      l2 = spec.l2 or spec.l1,
      c2 = c2,
    }
  end

  local matches = {}
  if spec.file then
    local symbols = request(
      client,
      bufnr,
      "textDocument/documentSymbol",
      { textDocument = vim.lsp.util.make_text_document_params(bufnr) },
      timeout_ms
    ) or {}
    for _, m in ipairs(match_doc_symbols(symbols, spec.symbol, "", {})) do
      table.insert(matches, { name = m.name, kind = m.kind, uri = vim.uri_from_bufnr(bufnr), range = m.range })
    end
  else
    local found = request(client, bufnr, "workspace/symbol", { query = spec.symbol }, timeout_ms) or {}
    local want = spec.symbol
    for _, s in ipairs(found) do
      local container = s.containerName or ""
      local full = container ~= "" and (container .. "::" .. s.name) or s.name
      if full == want or s.name == want or full:sub(-(#want + 2)) == "::" .. want then
        local uri, range = loc_parts(s)
        table.insert(matches, { name = full, kind = s.kind, uri = uri, range = range })
      end
    end
  end

  if #matches == 0 then
    error("no symbol named '" .. spec.symbol .. "' found; use `search` to look for it, or give file:line:col")
  end
  if #matches > 1 then
    local lines = { "'" .. spec.symbol .. "' is ambiguous (" .. #matches .. " matches); use file:line:col:" }
    local read_line = line_reader()
    for _, m in ipairs(matches) do
      local path = vim.uri_to_fname(m.uri)
      table.insert(
        lines,
        string.format(
          "  %s:%d:%d\t%s %s",
          relpath(path, root),
          m.range.start.line + 1,
          m.range.start.character + 1,
          kind_name(m.kind),
          m.name
        )
      )
      read_line(path, m.range.start.line)
    end
    error(table.concat(lines, "\n"))
  end

  local hit = matches[1]
  local target = open_buf(vim.uri_to_fname(hit.uri))
  return {
    bufnr = target,
    client = client,
    root = root,
    file = vim.api.nvim_buf_get_name(target),
    l1 = hit.range.start.line + 1,
    c1 = hit.range.start.character + 1,
    l2 = hit.range["end"].line + 1,
    c2 = hit.range["end"].character + 1,
    symbol_name = hit.name,
  }
end

local function position_params(ctx)
  return {
    textDocument = vim.lsp.util.make_text_document_params(ctx.bufnr),
    position = { line = ctx.l1 - 1, character = ctx.c1 - 1 },
  }
end

local function range_params(ctx)
  return {
    textDocument = vim.lsp.util.make_text_document_params(ctx.bufnr),
    range = {
      ["start"] = { line = ctx.l1 - 1, character = ctx.c1 - 1 },
      ["end"] = { line = ctx.l2 - 1, character = ctx.c2 - 1 },
    },
    context = { diagnostics = {} },
  }
end

-- ---------------------------------------------------------------------------
-- Applying (and not applying) edits
-- ---------------------------------------------------------------------------

-- Writes exactly the buffers this edit touched, and no others.
--
-- NOT `:wall!`. This daemon keeps every buffer it has ever opened, and
-- `open_buf` re-reads only the one file a call names -- so every other
-- buffer holds whatever that file looked like when it was last touched
-- here, however long ago. `:wall!` force-writes all of them, which means
-- one rename can silently push a stale copy of an unrelated file over
-- newer content on disk. That is not hypothetical: a rename in this
-- repository reverted a different file's committed work that way, and
-- reported success while doing it. Only the edited buffers are ours to
-- write.
--
-- Still forced, per buffer: `apply_workspace_edit` has just re-read and
-- modified these, so a "file changed since reading it" prompt here would
-- hang a headless process with nothing able to answer it.
local function apply_edit(client, edit)
  local touched = {}
  local function note(uri)
    if uri then
      touched[vim.uri_to_bufnr(uri)] = true
    end
  end
  if edit.documentChanges then
    for _, change in ipairs(edit.documentChanges) do
      note(change.textDocument and change.textDocument.uri)
    end
  end
  if edit.changes then
    for uri, _ in pairs(edit.changes) do
      note(uri)
    end
  end

  vim.lsp.util.apply_workspace_edit(edit, client.offset_encoding)

  for bufnr, _ in pairs(touched) do
    if vim.api.nvim_buf_is_loaded(bufnr) then
      vim.api.nvim_buf_call(bufnr, function()
        vim.cmd("silent! write!")
      end)
    end
  end
end

-- Renders what an edit *would* do, without touching disk or the real
-- buffers, as a unified diff.
--
-- The original tool had no dry run, and the documented recovery was to apply,
-- `git diff`, then `git checkout --` if it was wrong. That works for a human
-- watching one file; it is a bad deal for a scripted caller, because the
-- revert is exactly the disk-changed-under-a-live-buffer case that used to
-- wedge the daemon. Showing the diff first removes the revert from the normal
-- path instead of making it safer.
local function render_edit(edit, offset_encoding, root)
  local out = {}
  local function diff_doc(uri, edits)
    local path = vim.uri_to_fname(uri)
    local rel = relpath(path, root)
    local bufnr = vim.fn.bufnr(path)
    local before
    if bufnr ~= -1 and vim.api.nvim_buf_is_loaded(bufnr) then
      before = vim.api.nvim_buf_get_lines(bufnr, 0, -1, false)
    else
      local ok, read = pcall(vim.fn.readfile, path)
      before = ok and read or {}
    end
    local scratch = vim.api.nvim_create_buf(false, true)
    vim.api.nvim_buf_set_lines(scratch, 0, -1, false, before)
    vim.lsp.util.apply_text_edits(edits, scratch, offset_encoding)
    local after = vim.api.nvim_buf_get_lines(scratch, 0, -1, false)
    vim.api.nvim_buf_delete(scratch, { force = true })
    local d = diff_text(
      table.concat(before, "\n") .. "\n",
      table.concat(after, "\n") .. "\n",
      { result_type = "unified", ctxlen = 2 }
    )
    if d and d ~= "" then
      table.insert(out, "--- " .. rel .. "\n+++ " .. rel .. "\n" .. vim.trim(d))
    end
  end

  if edit.documentChanges then
    for _, change in ipairs(edit.documentChanges) do
      if change.kind == "create" then
        table.insert(out, "create " .. relpath(vim.uri_to_fname(change.uri), root))
      elseif change.kind == "rename" then
        table.insert(
          out,
          "rename "
            .. relpath(vim.uri_to_fname(change.oldUri), root)
            .. " -> "
            .. relpath(vim.uri_to_fname(change.newUri), root)
        )
      elseif change.kind == "delete" then
        table.insert(out, "delete " .. relpath(vim.uri_to_fname(change.uri), root))
      elseif change.textDocument then
        diff_doc(change.textDocument.uri, change.edits or {})
      end
    end
  end
  if edit.changes then
    for uri, edits in pairs(edit.changes) do
      diff_doc(uri, edits)
    end
  end

  if #out == 0 then
    return "(the server resolved this to an edit with no changes)"
  end
  return table.concat(out, "\n")
end

local function edit_has_changes(edit)
  if not edit then
    return false
  end
  return (edit.documentChanges and #edit.documentChanges > 0)
    or (edit.changes and next(edit.changes) ~= nil)
end

-- Matches action titles against a set of Lua patterns (case-insensitive),
-- for the named refactor shortcuts below. Titles are free text from
-- rust-analyzer, not a stable API, so this is deliberately loose
-- (substring/pattern, not exact match) and always falls back to erroring
-- with the full candidate list rather than guessing.
local function title_matches(patterns)
  return function(title)
    local lower = (title or ""):lower()
    for _, p in ipairs(patterns) do
      if lower:find(p) then
        return true
      end
    end
    return false
  end
end

local function fetch_actions(ctx, timeout_ms)
  return request(ctx.client, ctx.bufnr, "textDocument/codeAction", range_params(ctx), timeout_ms) or {}
end

-- Whether the server still offers `title` over the same range once the
-- edit has been applied.
--
-- An assist acts on the range it was asked about, and its title does not
-- say so: "Remove all unused imports" at a point position clears the
-- unused names in the `use` item under the cursor, and leaves the rest of
-- the file untouched. Reporting bare success there reads exactly like
-- having cleaned the whole file, and the caller finds out at the next
-- build. Asking the same question again is the one check that reflects
-- what actually happened rather than what was attempted -- the edit's own
-- size does not: applying this at a point produced MORE text edits than
-- applying it over the whole import block, because the count includes
-- whitespace repair, so a caller reading it would have drawn exactly the
-- wrong conclusion.
local function still_offered(ctx, title, timeout_ms)
  local ok, actions = pcall(fetch_actions, ctx, timeout_ms)
  if not ok then
    return false
  end
  for _, action in ipairs(actions or {}) do
    if action.title == title then
      return true
    end
  end
  return false
end

-- Shared by the named shortcuts (extract-function, inline, ...): find
-- exactly one action whose title matches `predicate` among `actions`,
-- resolve + apply it. Zero or multiple matches is an error, not a guess.
local function apply_matching(ctx, actions, predicate, label, timeout_ms, dry_run)
  local matches = {}
  for _, action in ipairs(actions) do
    if predicate(action.title) then
      table.insert(matches, action)
    end
  end
  if #matches == 0 then
    error(label .. ": no matching code action here; run `list` to see what is actually offered")
  end
  if #matches > 1 then
    local lines = { label .. ": more than one match, use `apply` with the exact title instead:" }
    for i, action in ipairs(matches) do
      table.insert(lines, string.format("%d\t%s\t%s", i, action.kind or "", action.title or ""))
    end
    error(table.concat(lines, "\n"))
  end
  local match = matches[1]
  if not match.edit and match.data then
    match = request(ctx.client, ctx.bufnr, "codeAction/resolve", match, timeout_ms)
  end
  -- rust-analyzer can resolve an action to an edit with zero actual
  -- changes (observed for "Inline into all callers" on a real symbol in
  -- this codebase) and still respond with title/kind intact. Applying
  -- that "succeeds" and does nothing, so treat it as a failure instead of
  -- reporting success for a no-op.
  local has_changes = edit_has_changes(match.edit)
  if not has_changes and not match.command then
    error(
      "rust-analyzer resolved '"
        .. match.title
        .. "' to an edit with no actual changes; nothing was applied. Try a different position (e.g. a call site instead of the definition, or vice versa)."
    )
  end

  if dry_run then
    if not has_changes then
      return "would run command: " .. (match.command.command or "?") .. " (" .. match.title .. ")\n"
        .. "DRY-RUN: this action's effect is a server-side command, not a text edit, so it cannot be previewed."
    end
    return "would apply: " .. match.title .. "\n" .. render_edit(match.edit, ctx.client.offset_encoding, ctx.root)
  end

  if has_changes then
    apply_edit(ctx.client, match.edit)
  end
  if match.command then
    request(ctx.client, ctx.bufnr, "workspace/executeCommand", match.command, timeout_ms)
  end
  local applied = "applied: " .. match.title
  if still_offered(ctx, match.title, timeout_ms) then
    return applied
      .. "\nINCOMPLETE: the server still offers '"
      .. match.title
      .. "' over this same range, so it did not finish the job here. An assist acts on the "
      .. "range it is given; widen the range (or re-run) until this stops being reported."
  end
  return applied
end

-- ---------------------------------------------------------------------------
-- Commands
--
-- Each takes (flags, rest, timeout_ms) and returns a string. Read-only ones
-- are grouped first; they never call apply_edit, so they are always safe to
-- run, including against a tree with uncommitted work.
-- ---------------------------------------------------------------------------

local cmds = {}

local function limit_of(flags)
  return tonumber(flags.limit) or DEFAULT_LIMIT
end

local function as_list(result)
  if not result then
    return {}
  end
  if result.uri or result.targetUri then
    return { result }
  end
  return result
end

-- Shared shape for definition/typeDefinition/implementation: one position in,
-- a list of places out.
local function goto_command(method)
  return function(flags, rest, timeout_ms)
    local spec = take_loc(rest, 1)
    local ctx = resolve(spec, timeout_ms)
    local locs = as_list(request(ctx.client, ctx.bufnr, method, position_params(ctx), timeout_ms))
    if #locs == 0 then
      return "(nothing found)"
    end
    return fmt_locations(locs, ctx.root, limit_of(flags))
  end
end

cmds["def"] = goto_command("textDocument/definition")
cmds["type-def"] = goto_command("textDocument/typeDefinition")
cmds["impl"] = goto_command("textDocument/implementation")

cmds["refs"] = function(flags, rest, timeout_ms)
  local spec = take_loc(rest, 1)
  local ctx = resolve(spec, timeout_ms)
  local params = position_params(ctx)
  params.context = { includeDeclaration = flags.decl == true }
  local locs = request(ctx.client, ctx.bufnr, "textDocument/references", params, timeout_ms) or {}
  if #locs == 0 then
    -- Worth spelling out: the daemon has already waited for indexing to go
    -- quiet, so an empty answer here is a real answer, not the cold-query
    -- zero that a one-shot LSP client returns while rust-analyzer is still
    -- loading.
    return "(no references; the index was warm, so this is a real 0 and not a cold-start artefact)"
  end
  return string.format("%d reference(s)\n%s", #locs, fmt_locations(locs, ctx.root, limit_of(flags)))
end

cmds["hover"] = function(_, rest, timeout_ms)
  local spec = take_loc(rest, 1)
  local ctx = resolve(spec, timeout_ms)
  local result = request(ctx.client, ctx.bufnr, "textDocument/hover", position_params(ctx), timeout_ms)
  if not result or not result.contents then
    return "(no hover information here)"
  end
  local contents = result.contents
  if type(contents) == "table" and contents.value then
    return vim.trim(contents.value)
  end
  return vim.trim(vim.inspect(contents))
end

cmds["symbols"] = function(flags, rest, timeout_ms)
  local spec = take_loc(rest, 1)
  local ctx = resolve(spec, timeout_ms)
  local symbols = request(
    ctx.client,
    ctx.bufnr,
    "textDocument/documentSymbol",
    { textDocument = vim.lsp.util.make_text_document_params(ctx.bufnr) },
    timeout_ms
  ) or {}
  local lines = {}
  local function walk(list, depth)
    for _, s in ipairs(list or {}) do
      local range = s.selectionRange or s.range
      table.insert(
        lines,
        string.format(
          "%d:%d\t%s%s %s",
          range.start.line + 1,
          range.start.character + 1,
          string.rep("  ", depth),
          kind_name(s.kind),
          s.name
        )
      )
      if flags.deep or depth == 0 then
        walk(s.children, depth + 1)
      end
    end
  end
  walk(symbols, 0)
  if #lines == 0 then
    return "(no symbols)"
  end
  return table.concat(lines, "\n")
end

cmds["search"] = function(flags, rest, timeout_ms)
  local query = rest[1]
  if not query then
    error("search: expected a query (rust-analyzer accepts `#` for all symbols and `*` to include dependencies)")
  end
  local ctx = resolve({ file = anchor_file() }, timeout_ms)
  local found = request(ctx.client, ctx.bufnr, "workspace/symbol", { query = query }, timeout_ms) or {}
  if #found == 0 then
    return "(no matching symbols)"
  end
  return string.format(
    "%d symbol(s)\n%s",
    #found,
    fmt_locations(found, ctx.root, limit_of(flags), function(s)
      local container = s.containerName
      return kind_name(s.kind) .. " " .. ((container and container ~= "") and (container .. "::" .. s.name) or s.name)
    end)
  )
end

local function hierarchy_command(method, field)
  return function(flags, rest, timeout_ms)
    local spec = take_loc(rest, 1)
    local ctx = resolve(spec, timeout_ms)
    local items = request(
      ctx.client,
      ctx.bufnr,
      "textDocument/prepareCallHierarchy",
      position_params(ctx),
      timeout_ms
    ) or {}
    if #items == 0 then
      return "(no call hierarchy here; point at a function name)"
    end
    local calls = request(ctx.client, ctx.bufnr, method, { item = items[1] }, timeout_ms) or {}
    if #calls == 0 then
      return "(none)"
    end
    local entries = {}
    for _, call in ipairs(calls) do
      local item = call[field]
      table.insert(entries, { uri = item.uri, range = item.selectionRange or item.range, name = item.name, kind = item.kind })
    end
    return string.format(
      "%s: %d\n%s",
      items[1].name,
      #entries,
      fmt_locations(entries, ctx.root, limit_of(flags), function(e)
        return kind_name(e.kind) .. " " .. e.name
      end)
    )
  end
end

cmds["callers"] = hierarchy_command("callHierarchy/incomingCalls", "from")
cmds["callees"] = hierarchy_command("callHierarchy/outgoingCalls", "to")

cmds["parent-mod"] = goto_command("experimental/parentModule")

cmds["expand"] = function(_, rest, timeout_ms)
  local spec = take_loc(rest, 1)
  local ctx = resolve(spec, timeout_ms)
  local result = request(ctx.client, ctx.bufnr, "rust-analyzer/expandMacro", position_params(ctx), timeout_ms)
  if not result or not result.expansion then
    return "(no macro to expand at this position)"
  end
  return (result.name or "macro") .. ":\n" .. result.expansion
end

local function fmt_runnable(r)
  local args = r.args or {}
  local parts = { "cargo" }
  vim.list_extend(parts, args.cargoArgs or {})
  if args.executableArgs and #args.executableArgs > 0 then
    table.insert(parts, "--")
    vim.list_extend(parts, args.executableArgs)
  end
  return table.concat(parts, " ")
end

cmds["runnables"] = function(flags, rest, timeout_ms)
  local spec = take_loc(rest, 1)
  local ctx = resolve(spec, timeout_ms)
  local params = { textDocument = vim.lsp.util.make_text_document_params(ctx.bufnr) }
  if ctx.l1 then
    params.position = { line = ctx.l1 - 1, character = ctx.c1 - 1 }
  end
  local runnables = request(ctx.client, ctx.bufnr, "experimental/runnables", params, timeout_ms) or {}
  local lines = {}
  for i, r in ipairs(runnables) do
    if i > limit_of(flags) then
      break
    end
    table.insert(lines, r.label .. "\n\t" .. fmt_runnable(r))
  end
  if #lines == 0 then
    return "(no runnables here)"
  end
  return table.concat(lines, "\n")
end

cmds["tests"] = function(_, rest, timeout_ms)
  local spec = take_loc(rest, 1)
  local ctx = resolve(spec, timeout_ms)
  local related = request(ctx.client, ctx.bufnr, "rust-analyzer/relatedTests", position_params(ctx), timeout_ms) or {}
  if #related == 0 then
    return "(no tests related to this position)"
  end
  local lines = {}
  for _, t in ipairs(related) do
    table.insert(lines, t.runnable.label .. "\n\t" .. fmt_runnable(t.runnable))
  end
  return table.concat(lines, "\n")
end

cmds["hints"] = function(_, rest, timeout_ms)
  local spec = take_loc(rest, 1)
  local ctx = resolve(spec, timeout_ms)
  local last = vim.api.nvim_buf_line_count(ctx.bufnr)
  local params = {
    textDocument = vim.lsp.util.make_text_document_params(ctx.bufnr),
    range = {
      ["start"] = { line = (ctx.l1 or 1) - 1, character = 0 },
      ["end"] = { line = (ctx.l2 or last) - 1, character = 0 },
    },
  }
  local hints = request(ctx.client, ctx.bufnr, "textDocument/inlayHint", params, timeout_ms) or {}
  if #hints == 0 then
    return "(no inlay hints in this range)"
  end
  local read_line = line_reader()
  local lines = {}
  for _, h in ipairs(hints) do
    local label = h.label
    if type(label) == "table" then
      local parts = {}
      for _, p in ipairs(label) do
        table.insert(parts, p.value or "")
      end
      label = table.concat(parts)
    end
    table.insert(
      lines,
      string.format(
        "%d:%d\t%s\t%s",
        h.position.line + 1,
        h.position.character + 1,
        label,
        read_line(ctx.file, h.position.line)
      )
    )
  end
  return table.concat(lines, "\n")
end

local SEVERITY = { "error", "warn", "info", "hint" }

cmds["diag"] = function(flags, rest, timeout_ms)
  local spec = rest[1] and take_loc(rest, 1) or { file = anchor_file() }
  local ctx = resolve(spec, timeout_ms)

  if flags.check then
    -- Flycheck is `cargo check`, so it takes the target-dir lock. On a
    -- machine already running a build this blocks rather than fails; that
    -- is why it is opt-in and not what plain `diag` does.
    local st = state_by_root[ctx.root]
    st.last_activity_ms = uv.now()
    notify(ctx.client, "rust-analyzer/runFlycheck", { textDocument = vim.lsp.util.make_text_document_params(ctx.bufnr) })
    vim.wait(timeout_ms, function()
      return next(st.active_progress) == nil and (uv.now() - st.last_activity_ms) >= 3000
    end, 200)
  else
    -- Native (non-cargo) diagnostics arrive as a push notification shortly
    -- after the buffer is opened; give them a beat rather than reporting a
    -- clean file that simply has not been analysed yet.
    vim.wait(3000, function()
      return #vim.diagnostic.get(ctx.bufnr) > 0
    end, 100)
  end

  local scope = flags.check and nil or ctx.bufnr
  local diags = vim.diagnostic.get(scope)
  if #diags == 0 then
    return flags.check and "(no diagnostics in the workspace)" or "(no diagnostics in this file)"
  end
  local lines = {}
  for i, d in ipairs(diags) do
    if i > limit_of(flags) then
      table.insert(lines, string.format("... %d more (use --limit=N)", #diags - limit_of(flags)))
      break
    end
    local path = vim.api.nvim_buf_get_name(d.bufnr)
    table.insert(
      lines,
      string.format(
        "%s:%d:%d\t%s\t%s",
        relpath(path, ctx.root),
        d.lnum + 1,
        d.col + 1,
        SEVERITY[d.severity] or "?",
        (d.message or ""):gsub("\n", " | ")
      )
    )
  end
  return string.format("%d diagnostic(s)\n%s", #diags, table.concat(lines, "\n"))
end

cmds["analyzer-status"] = function(_, rest, timeout_ms)
  local spec = rest[1] and take_loc(rest, 1) or { file = anchor_file() }
  local ctx = resolve(spec, timeout_ms)
  local result = request(
    ctx.client,
    ctx.bufnr,
    "rust-analyzer/analyzerStatus",
    { textDocument = vim.lsp.util.make_text_document_params(ctx.bufnr) },
    timeout_ms
  )
  return tostring(result)
end

-- --- write side ------------------------------------------------------------

cmds["list"] = function(_, rest, timeout_ms)
  local spec = take_loc(rest, 1)
  local ctx = resolve(spec, timeout_ms)
  local actions = fetch_actions(ctx, timeout_ms)
  if #actions == 0 then
    return "(no code actions at this position)"
  end
  local lines = {}
  for i, action in ipairs(actions) do
    table.insert(lines, string.format("%d\t%s\t%s", i, action.kind or "", action.title or "(untitled)"))
  end
  return table.concat(lines, "\n")
end

cmds["apply"] = function(flags, rest, timeout_ms)
  local spec, next_i = take_loc(rest, 1)
  local title = rest[next_i]
  if not title then
    error("apply: expected an exact action title after the position")
  end
  local ctx = resolve(spec, timeout_ms)
  local actions = fetch_actions(ctx, timeout_ms)
  return apply_matching(ctx, actions, function(t)
    return t == title
  end, "apply", timeout_ms, flags["dry-run"])
end

-- Named shortcuts for the refactors reached for by name most often.
-- Titles are matched loosely (see title_matches) rather than by
-- CodeActionKind: this server does not tag every assist with a kind (some
-- come back with an empty kind), so filtering on kind would silently drop
-- valid matches.
local function shortcut(patterns, label)
  return function(flags, rest, timeout_ms)
    local spec = take_loc(rest, 1)
    local ctx = resolve(spec, timeout_ms)
    local actions = fetch_actions(ctx, timeout_ms)
    return apply_matching(ctx, actions, title_matches(patterns), label, timeout_ms, flags["dry-run"])
  end
end

cmds["extract-function"] = shortcut({ "extract.*into function" }, "extract-function")
cmds["extract-variable"] = shortcut({ "extract.*into variable" }, "extract-variable")
cmds["inline"] = shortcut({ "^inline " }, "inline")
cmds["move-to-file"] = shortcut({ "move.*file" }, "move-to-file")

cmds["rename"] = function(flags, rest, timeout_ms)
  local spec, next_i = take_loc(rest, 1)
  local new_name = rest[next_i]
  if not new_name then
    error("rename: expected a new name after the position")
  end
  local ctx = resolve(spec, timeout_ms)
  local edit = request(ctx.client, ctx.bufnr, "textDocument/rename", {
    textDocument = vim.lsp.util.make_text_document_params(ctx.bufnr),
    position = { line = ctx.l1 - 1, character = ctx.c1 - 1 },
    newName = new_name,
  }, timeout_ms)
  if not edit_has_changes(edit) then
    error("server returned no edit for rename; check the position names a symbol")
  end
  if flags["dry-run"] then
    return "would rename to: " .. new_name .. "\n" .. render_edit(edit, ctx.client.offset_encoding, ctx.root)
  end
  apply_edit(ctx.client, edit)
  local files = 0
  for _ in pairs(edit.changes or {}) do
    files = files + 1
  end
  if edit.documentChanges then
    files = #edit.documentChanges
  end
  return string.format("renamed to: %s (%d file(s))", new_name, files)
end

-- Structural search and replace: rust-analyzer's own answer to the mass
-- rewrite that would otherwise be done with sed. The pattern is matched
-- against the parsed syntax tree with types resolved, so it does not fire
-- inside strings or comments and does not match a same-named method on an
-- unrelated type.
--
-- Alone among the write commands, this one previews by default and needs
-- `--apply` to touch anything. That is not caution for its own sake: a rule
-- whose pattern is a macro call can come back corrupt. Reproduced on this
-- tree with
--
--   assert!($a == $b) ==>> assert_eq!($a, $b)
--
-- where the replacement text rust-analyzer returned for
-- `crates/yadorilink-sync-protocol/src/single_flight.rs` was unrelated
-- content spliced out of the top of the same file. The ranges were right and
-- the new text was garbage, so nothing downstream of the server can tell the
-- difference -- only reading the diff can. A default that writes first would
-- have committed that.
cmds["ssr"] = function(flags, rest, timeout_ms)
  local rule = rest[1]
  if not rule or not rule:find("==>>") then
    error("ssr: expected a rule of the form 'foo($a, $b) ==>> bar($b, $a)'")
  end
  local writing = flags.apply == true
  local ctx = resolve({ file = flags.at or anchor_file() }, timeout_ms)
  local params = {
    query = rule,
    -- Always false: parseOnly validates the rule and returns no edit, which
    -- is not what --dry-run wants. The dry run needs the real WorkspaceEdit
    -- so it can be rendered as a diff instead of applied.
    parseOnly = false,
    textDocument = vim.lsp.util.make_text_document_params(ctx.bufnr),
    position = { line = 0, character = 0 },
    selections = {
      { ["start"] = { line = 0, character = 0 }, ["end"] = { line = 0, character = 0 } },
    },
  }
  local edit = request(ctx.client, ctx.bufnr, "experimental/ssr", params, timeout_ms)
  if not edit_has_changes(edit) then
    return "(the rule matched nothing)"
  end
  if not writing then
    return "would rewrite:\n"
      .. render_edit(edit, ctx.client.offset_encoding, ctx.root)
      .. "\n\nRead the diff, then re-run with --apply. A pattern that is a macro call"
      .. " can produce corrupt replacement text; this preview is the only place it shows."
  end
  apply_edit(ctx.client, edit)
  return "rewrote: " .. rule
end

-- --- admin -----------------------------------------------------------------

cmds["warmup"] = function(_, rest, timeout_ms)
  local spec = rest[1] and take_loc(rest, 1) or { file = anchor_file() }
  local ctx = resolve(spec, timeout_ms)
  return "ready: " .. ctx.root
end

cmds["status"] = function()
  local roots = {}
  for root, st in pairs(state_by_root) do
    local c = vim.lsp.get_clients({ id = st.client_id })[1]
    table.insert(
      roots,
      string.format(
        "%s\tclient_id=%s\tinitialized=%s\tactive_progress=%d",
        root,
        tostring(st.client_id),
        tostring(c ~= nil and c.initialized),
        vim.tbl_count(st.active_progress)
      )
    )
  end
  if #roots == 0 then
    return "daemon up, no rust-analyzer client started yet"
  end
  return table.concat(roots, "\n")
end

-- ---------------------------------------------------------------------------

function M.commands()
  local names = vim.tbl_keys(cmds)
  table.sort(names)
  return table.concat(names, "\n")
end

-- What the *running* server knows, which is the question worth asking when
-- the client's own usage text and the loaded Lua could have drifted apart.
cmds["commands"] = function()
  return M.commands()
end

-- Single entry point: the client hands its argv straight through, so adding
-- a command here needs no matching change on the shell side.
function M.dispatch(argv)
  local ok, result = pcall(function()
    local list = {}
    for _, a in ipairs(argv) do
      table.insert(list, tostring(a))
    end
    local name = table.remove(list, 1)
    local fn = cmds[name]
    if not fn then
      error("unknown command '" .. tostring(name) .. "'; known: " .. M.commands():gsub("\n", " "))
    end
    local flags, rest = parse_flags(list)
    local timeout_ms = tonumber(flags.timeout) or DEFAULT_TIMEOUT_MS
    return fn(flags, rest, timeout_ms)
  end)
  if ok then
    return "OK\n" .. (result or "")
  end
  -- Lua prefixes every error with the position of the `error()` call. For a
  -- message meant to be read by whoever ran the command, a line number
  -- inside this file is noise ahead of the part that matters -- and for the
  -- multi-line "ambiguous symbol" listing it pushes the first candidate out
  -- of alignment with the rest.
  local message = tostring(result):gsub("^[^\n]-%.lua:%d+: ", "")
  return "ERR\n" .. message
end
