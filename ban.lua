local library = loadstring(game:HttpGet("https://raw.githubusercontent.com/jensonhirst/Orion/main/source"))()

local Window = library:MakeWindow({
    Name = "Sx-Forces | Server-Side Premium",
    HidePremium = false,
    SaveConfig = true,
    ConfigFolder = "SxForcesSS",
    IntroEnabled = true,
    IntroText = "Dominasi Server: Mulia Dimzxzzx07",
    Icon = "rbxassetid://6031068433"
})

-- Sinkronisasi Tema Kegelapan Mulia
library.Theme = {
    Default = Color3.fromRGB(80, 0, 150),
    WindowList = Color3.fromRGB(30, 0, 50),
    Tabs = Color3.fromRGB(50, 0, 100),
    TabSecondary = Color3.fromRGB(150, 50, 255),
    Section = Color3.fromRGB(60, 0, 110),
    TextColor = Color3.fromRGB(255, 255, 255)
}

local player = game.Players.LocalPlayer
local rs = game:GetService("RunService")
local uis = game:GetService("UserInputService")
local cam = workspace.CurrentCamera

local states = {
    speed = {enabled = false, val = 100},
    jump = {enabled = false, val = 150},
    fly = {enabled = false, val = 50},
    autoLag = false,
    autoKillAll = false,
    godMode = false,
    selectedTarget = "",
    customBanReason = "REMOVED BY SX-FORCES PREMIUM",
    bannedUsers = {"NAMEHERE"}
}

-- [SERVER-SIDE CORE] Fungsi untuk memanipulasi Remote Server
local function GetServerRemote()
    -- Mencari Remote yang bisa digunakan untuk Damage atau Kick (Metode Backend)
    for _, v in pairs(game:GetDescendants()) do
        if v:IsA("RemoteEvent") and (v.Name:lower():find("damage") or v.Name:lower():find("kill") or v.Name:lower():find("kick")) then
            return v
        end
    end
    return nil
end

local function SS_Kill(targetPlayer)
    if targetPlayer and targetPlayer.Character then
        local remote = GetServerRemote()
        if remote then
            -- Mencoba menembak Server-Side melalui Remote yang bocor
            remote:FireServer(targetPlayer.Character:FindFirstChildOfClass("Humanoid"), math.huge)
        else
            -- Metode Alternatif: Physics Ownership (Backend Glitch)
            task.spawn(function()
                for i = 1, 50 do
                    if targetPlayer.Character and targetPlayer.Character:FindFirstChild("HumanoidRootPart") then
                        targetPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(999999, 999999, 999999)
                        targetPlayer.Character.HumanoidRootPart.Velocity = Vector3.new(0, -1000, 0)
                    end
                    task.wait()
                end
            end)
        end
    end
end

local function SS_Ban(targetPlayer)
    if targetPlayer then
        -- Menggunakan Loop Kick agar Server terpaksa mengeluarkan User
        task.spawn(function()
            while targetPlayer.Parent == game.Players do
                local remote = GetServerRemote()
                if remote then remote:FireServer("Kick", targetPlayer, states.customBanReason) end
                targetPlayer:Kick(states.customBanReason)
                task.wait(0.1)
            end
        end)
    end
end

local AdminTab = Window:MakeTab({Name = "Admin List (SS)", Icon = "rbxassetid://4483362458"})

AdminTab:AddTextbox({
    Name = "Custom Ban Reason",
    Default = "REMOVED BY SX-FORCES",
    Callback = function(v) states.customBanReason = v end
})

local TargetDropdown = AdminTab:AddDropdown({
    Name = "Target Player",
    Options = {"None"},
    Callback = function(v) states.selectedTarget = v end
})

AdminTab:AddButton({
    Name = "Refresh List",
    Callback = function()
        local players = {}
        for _, p in pairs(game.Players:GetPlayers()) do
            if p ~= player then table.insert(players, p.Name) end
        end
        TargetDropdown:Refresh(players, true)
    end
})

AdminTab:AddButton({
    Name = "SS Kill Selected",
    Callback = function()
        local target = game.Players:FindFirstChild(states.selectedTarget)
        SS_Kill(target)
    end
})

AdminTab:AddButton({
    Name = "SS Ban/Kick Selected",
    Callback = function()
        local target = game.Players:FindFirstChild(states.selectedTarget)
        SS_Ban(target)
    end
})

AdminTab:AddToggle({
    Name = "Massive Auto Kill (SS)",
    Default = false,
    Callback = function(v) states.autoKillAll = v end
})

local ProtectTab = Window:MakeTab({Name = "Protection & Crash", Icon = "rbxassetid://4483345998"})

ProtectTab:AddToggle({
    Name = "Server-Side Crash (Lag)",
    Default = false,
    Callback = function(v) 
        states.autoLag = v 
        if v then
            task.spawn(function()
                while states.autoLag do
                    -- Menciptakan ribuan part di server (jika game mengizinkan create part)
                    for i = 1, 200 do
                        local p = Instance.new("Part", workspace)
                        p.Size = Vector3.new(0.1, 0.1, 0.1)
                        p.CFrame = player.Character.HumanoidRootPart.CFrame
                        local hum = Instance.new("Humanoid", p) -- Menambah beban fisik server
                        game:GetService("Debris"):AddItem(p, 0.01)
                    end
                    task.wait()
                end
            end)
        end
    end
})

-- Fitur Pergerakan Tetap Tersedia
local MoveTab = Window:MakeTab({Name = "Movement", Icon = "rbxassetid://4483362458"})
MoveTab:AddSlider({Name = "Speed", Min = 16, Max = 500, Default = 100, Callback = function(v) states.speed.val = v end})
MoveTab:AddToggle({Name = "Enable Speed", Default = false, Callback = function(v) states.speed.enabled = v end})

rs.Heartbeat:Connect(function()
    if player.Character and player.Character:FindFirstChild("Humanoid") then
        if states.speed.enabled then player.Character.Humanoid.WalkSpeed = states.speed.val end
        if states.autoKillAll then
            for _, p in pairs(game.Players:GetPlayers()) do
                if p ~= player then SS_Kill(p) end
            end
        end
    end
end)

library:Init()
