local library = loadstring(game:HttpGet("https://raw.githubusercontent.com/jensonhirst/Orion/main/source"))()

local Window = library:MakeWindow({
    Name = "Sx-Forces | Ultimate SS Bypass",
    HidePremium = false,
    SaveConfig = true,
    ConfigFolder = "SxForcesV3",
    IntroEnabled = true,
    IntroText = "Akses Tak Terbatas: Mulia Dimzxzzx07",
    Icon = "rbxassetid://6031068433"
})

-- Identitas Banned & Security List
local SecurityBypass = {
    ["BannedUserName1"] = true,
    ["rustysillyband"] = true,
    ["AntiExploit"] = false,
    ["Adonis"] = false
}

local player = game.Players.LocalPlayer
local rs = game:GetService("RunService")
local uis = game:GetService("UserInputService")
local logService = game:GetService("LogService")
local teleportService = game:GetService("TeleportService")

local states = {
    speed = {enabled = false, val = 100},
    jump = {enabled = false, val = 150},
    antiKick = true,
    autoLag = false,
    autoKillAll = false,
    selectedTarget = "",
    customBanReason = "REMOVED BY SX-FORCES PREMIUM",
    bypassSecurity = true
}

-- [BYPASS & ANTI-DETECTION SYSTEM]
-- Melumpuhkan pengecekan integritas dari skrip anti-cheat map
local mt = getrawmetatable(game)
local oldNamecall = mt.__namecall
setreadonly(mt, false)

mt.__namecall = newcclosure(function(self, ...)
    local method = getnamecallmethod()
    local args = {...}
    
    -- Mematikan deteksi Kick dan deteksi Remote mencurigakan
    if states.antiKick and (tostring(method) == "Kick" or tostring(method) == "BreakJoints") then
        if self == player or self == player.Character then
            return nil 
        end
    end
    
    -- Bypass deteksi kecepatan/jump dari server
    if tostring(method) == "FireServer" and tostring(self):find("Anticheat") then
        return nil
    end

    return oldNamecall(self, unpack(args))
end)
setreadonly(mt, true)

-- [CONSOLE LOGGING SYSTEM]
local function createConsole()
    local ConsoleTab = Window:MakeTab({Name = "Console Logs", Icon = "rbxassetid://4483345998"})
    local logBox = ConsoleTab:AddParagraph("System Output", "Menunggu data dari server...")
    
    logService.MessageOut:Connect(function(msg, msgType)
        logBox:Set("Type: " .. tostring(msgType) .. "\nLog: " .. msg)
    end)
end

-- [SERVER-SIDE CORE EXPLOITATION]
local function FindVulnerableRemote()
    for _, v in pairs(game:GetDescendants()) do
        if v:IsA("RemoteEvent") then
            -- Mencari remote yang sering bocor ke backend
            local n = v.Name:lower()
            if n:find("damage") or n:find("kill") or n:find("admin") or n:find("mod") or n:find("ban") then
                return v
            end
        end
    end
    return nil
end

local function SS_Execute(action, target)
    local remote = FindVulnerableRemote()
    if action == "Kill" and target.Character then
        if remote then remote:FireServer(target.Character:FindFirstChildOfClass("Humanoid"), math.huge) end
        -- Backup: Physics Glitch
        target.Character:BreakJoints()
    elseif action == "Ban" and target then
        if remote then remote:FireServer("Ban", target, states.customBanReason) end
        target:Kick(states.customBanReason)
    end
end

-- [GUI TABS]
local AdminTab = Window:MakeTab({Name = "Admin List (SS)", Icon = "rbxassetid://4483362458"})

AdminTab:AddTextbox({
    Name = "Reason Hukuman",
    Default = "BYPASS BY SX-FORCES",
    Callback = function(v) states.customBanReason = v end
})

local TargetDropdown = AdminTab:AddDropdown({
    Name = "Pilih Target",
    Options = {"Refresh untuk update"},
    Callback = function(v) states.selectedTarget = v end
})

AdminTab:AddButton({
    Name = "Refresh List",
    Callback = function()
        local plrs = {}
        for _, p in pairs(game.Players:GetPlayers()) do
            if p ~= player then table.insert(plrs, p.Name) end
        end
        TargetDropdown:Refresh(plrs, true)
    end
})

AdminTab:AddButton({Name = "SS Kill", Callback = function() SS_Execute("Kill", game.Players:FindFirstChild(states.selectedTarget)) end})
AdminTab:AddButton({Name = "SS Ban", Callback = function() SS_Execute("Ban", game.Players:FindFirstChild(states.selectedTarget)) end})
AdminTab:AddToggle({Name = "Auto Kill All", Default = false, Callback = function(v) states.autoKillAll = v end})

local ProtectTab = Window:MakeTab({Name = "Bypass & Protection", Icon = "rbxassetid://4483345998"})

ProtectTab:AddToggle({Name = "Anti-Kick (Active)", Default = true, Callback = function(v) states.antiKick = v end})
ProtectTab:AddToggle({Name = "Bypass Security Map", Default = true, Callback = function(v) states.bypassSecurity = v end})

ProtectTab:AddToggle({
    Name = "Server-Side Lag",
    Default = false,
    Callback = function(v) 
        states.autoLag = v 
        task.spawn(function()
            while states.autoLag do
                for i = 1, 100 do
                    local p = Instance.new("Part", workspace)
                    p.Transparency = 1; p.CanCollide = false
                    Instance.new("Humanoid", p)
                    game:GetService("Debris"):AddItem(p, 0.01)
                end
                task.wait()
            end
        end)
    end
})

local MoveTab = Window:MakeTab({Name = "Movement", Icon = "rbxassetid://4483362458"})
MoveTab:AddSlider({Name = "Speed", Min = 16, Max = 500, Default = 100, Callback = function(v) states.speed.val = v end})
MoveTab:AddToggle({Name = "Enable Speed", Default = false, Callback = function(v) states.speed.enabled = v end})

-- Inisialisasi Fitur Console
createConsole()

rs.Heartbeat:Connect(function()
    if player.Character and player.Character:FindFirstChild("Humanoid") then
        if states.speed.enabled then player.Character.Humanoid.WalkSpeed = states.speed.val end
        if states.autoKillAll then
            for _, p in pairs(game.Players:GetPlayers()) do
                if p ~= player then SS_Execute("Kill", p) end
            end
        end
    end
end)

library:Init()
