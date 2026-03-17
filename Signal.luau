local Quartz = loadstring(game:HttpGet("https://github.com/notpoiu/Quartz/releases/latest/download/Quartz.luau", true))()
local Tester = Quartz.new({Timeout = 60})
Tester:TestAll()
Tester:PatchEnvironment()
local Signal = {}
local Signals = {}
local SignalsByName = {}
function Signal.new(Name)
    local Bindable = Instance.new("BindableEvent")
    Bindable.Name = Name
    Signals[Bindable.Event] = Bindable
    SignalsByName[Name] = Bindable
    return Bindable.Event
end
function Signal.Fire(Arg, ...)
    local ArgType = typeof(Arg)
    if ArgType == "RBXScriptSignal" then
        local Bindable = Signals[Arg]
        if Bindable then
            Bindable:Fire(...)
            return
        end
        if firesignal and typeof(firesignal) == "function" then
            firesignal(Arg, ...)
            return
        end
        if replicatesignal and typeof(replicatesignal) == "function" then
            replicatesignal(Arg, ...)
            return
        end
        return
    elseif ArgType == "Instance" and Arg:IsA("BindableEvent") then
        Arg:Fire(...)
    elseif ArgType == "string" then
        local Bindable = SignalsByName[Arg]
        if Bindable then
            Bindable:Fire(...)
            return
        end
    end
end
return Signal
