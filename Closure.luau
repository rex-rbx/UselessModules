local newl = function(fnc)
    local fnc = fnc -- 🙏 localize it
    return function(...)
        return fnc(...)
    end
end
local newc = function(fnct)
	local returned = ccoroutine.wrap(function(...)
		local ret = {
			coroutine.yield()
		}
		while true do
			ret = {
				coroutine.yield(
					fnct(
						(table and table.unpack or unpack)(ret)
					)
				)
			}
		end
	end)
	returned()
	return returned
end
local isl = function(fnct)
  return debug.info(fnct, "s") ~= "[C]"
end
local isc = function(fnct)
  return debug.info(fnct, "s") == "[C]"
end
return {newcclosure = newc, newlclosure = newl, clonefunction = newl, clonefunc = newl, cloneclosure = newl, islclosure = isl, iscclosure = isc, isluaclosure = isl}
