-- Mocks of the firmware Lua bindings the generated rules use. The test
-- appends the generated script and a scenario after this file.
local now = 0
local subs = {}
broadcasts = {}
publishes = {}

Log = { info = function() end, warn = function() end, error = function() end }
Config = { get = function(k)
  if k == "temperature.unit" then return "C" end
  if k == "mqtt.topic_prefix" then return "thesada/t/d" end
  return nil
end }
Node = { uptime = function() return now end }
EventBus = { subscribe = function(ev, fn) subs[ev] = fn end }
Telegram = { broadcast = function(msg, code)
  broadcasts[#broadcasts + 1] = { msg = msg, code = code }
  return true
end }
MQTT = { publish = function(topic, payload)
  publishes[#publishes + 1] = { topic = topic, payload = payload }
  return true
end }

function advance(ms) now = now + ms end
function fire(ev, data) subs[ev](data) end
function expect(cond, what)
  if not cond then error("FAIL: " .. what, 2) end
end
