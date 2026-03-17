local Set = function(key, value)
  assert(typeof(key) == "string" or typeof(key) == "number" or typeof(key) == "boolean", "Type of passed argument 'key' to setfflag is not supported."
  assert(typeof(value) == "string" or typeof(value) == "number" or typeof(value) == "boolean", "Type of passed argument 'value' to setfflag is not supported."
  return game:DefineFastFlag(tostring(key), tostring(value))
end
local Get = function(key)
      assert(typeof(key) == "string" or typeof(key) == "number" or typeof(key) == "boolean", "Type of passed argument 'key' to getfflag is not supported."
      return game:GetFastFlag(tostring(key))
end
return {getfflag = Get, setfflag = Set}
