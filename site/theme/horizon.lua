-- Horizon's pandoc filter.

-- Wide tables scroll inside their own frame.
function Table(t)
  return pandoc.Div({ t }, pandoc.Attr("", { "table-wrap" }))
end

-- In a `::: tier` row, each `[text]{.box}` span becomes a box of its own.
function Div(d)
  if not d.classes:includes("tier") then
    return nil
  end
  local boxes = {}
  for _, block in ipairs(d.content) do
    if block.t == "Para" or block.t == "Plain" then
      for _, inline in ipairs(block.content) do
        if inline.t == "Span" then
          table.insert(boxes, pandoc.Div({ pandoc.Plain(inline.content) }, inline.attr))
        end
      end
    else
      table.insert(boxes, block)
    end
  end
  d.content = boxes
  return d
end

-- A ```toml example also gets json and nix versions, as tabs, from the converter
-- named by $CONFIGTABS. `<!-- toml only -->` before a block keeps it as it is, and
-- `<!-- formats: toml json -->` picks the versions.
local configtabs = os.getenv("CONFIGTABS")
local labels = { toml = "TOML", json = "JSON", nix = "Nix" }

local function versions(code, formats)
  local tabs = {}
  for _, f in ipairs(formats) do
    local text = code
    if f ~= "toml" then
      text = pandoc.pipe(configtabs, { f }, code):gsub("%s+$", "")
      if f == "nix" then
        text = "services.sitescope.settings = " .. text .. ";"
      end
    end
    local block = pandoc.CodeBlock(text, pandoc.Attr("", { f }))
    table.insert(tabs, pandoc.Div({ block }, pandoc.Attr("", { "config-tab" }, { { "data-format", f }, { "data-label", labels[f] } })))
  end
  return pandoc.Div(tabs, pandoc.Attr("", { "config-tabs" }))
end

function Blocks(blocks)
  if not configtabs then
    return nil
  end
  local out, formats = {}, nil
  for _, b in ipairs(blocks) do
    if b.t == "RawBlock" and b.format == "html" then
      local f = b.text:match("^<!%-%- formats: ([%a ]+) %-%->")
      if f then
        formats = {}
        for w in f:gmatch("%a+") do
          table.insert(formats, w)
        end
      elseif b.text:match("^<!%-%- toml only") then
        formats = { "toml" }
      end
      table.insert(out, b)
    elseif b.t == "CodeBlock" and b.classes:includes("toml") then
      local f = formats or { "toml", "json", "nix" }
      formats = nil
      if #f > 1 then
        table.insert(out, versions(b.text, f))
      else
        table.insert(out, b)
      end
    else
      formats = nil
      table.insert(out, b)
    end
  end
  return out
end
