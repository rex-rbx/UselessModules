-- this is for compat
local clone = setmetatable({}, {__index = debug})
local env = (getgenv and getgenv()) or getfenv(0)
if not debug.getconstant or not getconstant then
  clone.getconstant = debug.getconstant or getconstant or function() return nil end
  env.getconstant = clone.getconstant
end
if not debug.getconstants or not getconstants then
  clone.getconstant = debug.getconstants or getconstants or function() return {} end
  env.getconstants = clone.getconstants
end
if not debug.setupvalue or not setupvalue then
  clone.setconstant = debug.setconstant or setconstant or function() end
  env.setconstant = clone.setconstant
end
if not debug.getupvalue or not getupvalue then
  clone.getupvalue = debug.getupvalue or getupvalue or function() return nil end
  env.getupvalue = clone.getupvalue
end
if not debug.getupvalues or not getupvalues then
  clone.getupvalues = debug.getupvalues or getupvalues or function() return {} end
  env.getupvalues = clone.getupvalues
end
if not debug.setupvalue or not setupvalue then
  clone.setupvalue = debug.setupvalue or setupvalue or function() end
  env.setupvalue = clone.setupvalue
end
env.debug = clone
return true
