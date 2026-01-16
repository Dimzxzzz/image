local library = loadstring(game:HttpGet("https://raw.githubusercontent.com/jensonhirst/Orion/main/source"))()

local Window = library:MakeWindow({
    Name = "Sx-Forces | Ultimate Premium",
    HidePremium = false,
    SaveConfig = true,
    ConfigFolder = "SxForcesConfig",
    IntroEnabled = true,
    IntroText = "Welcome, To Sx-Forces Ultimate",
    Icon = "https://raw.githubusercontent.com/Dimzxzzz/image/refs/heads/main/IMG_20251025_050958_125.jpg"
})

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
local lp = game:GetService("Lighting")
local cam = workspace.CurrentCamera

local states = {
    speed = {enabled = false, val = 100},
    jump = {enabled = false, val = 150},
    fly = {enabled = false, val = 50},
    antiAFK = false,
    antiAdmin = false,
    fakeRank = {enabled = false, type = "Admin"},
    verified = false,
    selectedTarget = "",
    autoLag = false,
    autoKillAll = false,
    godMode = false
}

local function getPlayerList()
    local list = {}
    for _, v in pairs(game.Players:GetPlayers()) do
        if v ~= player then table.insert(list, v.Name) end
    end
    return list
end

local AdminTab = Window:MakeTab({Name = "Admin List", Icon = "rbxassetid://4483362458"})

local TargetDropdown = AdminTab:AddDropdown({
    Name = "Select Player",
    Default = "None",
    Options = getPlayerList(),
    Callback = function(v) states.selectedTarget = v end
})

AdminTab:AddButton({Name = "Refresh List", Callback = function() TargetDropdown:Refresh(getPlayerList(), true) end})

AdminTab:AddButton({
    Name = "Kill Selected",
    Callback = function()
        local target = game.Players:FindFirstChild(states.selectedTarget)
        if target and target.Character then
            target.Character:BreakJoints()
        end
    end
})

AdminTab:AddButton({
    Name = "Ban & Kick Selected",
    Callback = function()
        local target = game.Players:FindFirstChild(states.selectedTarget)
        if target then target:Kick("Banned by Sx-Forces t.me/sxforces") end
    end
})

AdminTab:AddButton({
    Name = "Teleport to Target",
    Callback = function()
        local target = game.Players:FindFirstChild(states.selectedTarget)
        if target and target.Character then
            player.Character.HumanoidRootPart.CFrame = target.Character.HumanoidRootPart.CFrame
        end
    end
})

AdminTab:AddToggle({
    Name = "Auto Kill All (Massive)",
    Default = false,
    Callback = function(v) states.autoKillAll = v end
})

local MoveTab = Window:MakeTab({Name = "Movement", Icon = "rbxassetid://4483362458"})

MoveTab:AddSlider({Name = "Fly Speed", Min = 10, Max = 500, Default = 50, Callback = function(v) states.fly.val = v end})
MoveTab:AddToggle({
    Name = "Enable Fly",
    Default = false,
    Callback = function(v) 
        states.fly.enabled = v
        local char = player.Character
        local hrp = char:FindFirstChild("HumanoidRootPart")
        if v and hrp then
            local bg = Instance.new("BodyGyro", hrp)
            local bv = Instance.new("BodyVelocity", hrp)
            bg.P = 9e4; bg.MaxTorque = Vector3.new(9e9, 9e9, 9e9)
            bv.MaxForce = Vector3.new(9e9, 9e9, 9e9)
            task.spawn(function()
                while states.fly.enabled do
                    bg.CFrame = cam.CFrame
                    bv.Velocity = (char.Humanoid.MoveDirection.Magnitude > 0) and (cam.CFrame:VectorToWorldSpace(char.Humanoid.MoveDirection).Unit * states.fly.val) or Vector3.new(0,0,0)
                    task.wait()
                end
                bg:Destroy(); bv:Destroy()
            end)
        end
    end
})

MoveTab:AddTextbox({Name = "Speed Value", Default = "100", Callback = function(v) states.speed.val = tonumber(v) end})
MoveTab:AddToggle({Name = "Enable Speed", Default = false, Callback = function(v) states.speed.enabled = v end})
MoveTab:AddTextbox({Name = "Jump Value", Default = "150", Callback = function(v) states.jump.val = tonumber(v) end})
MoveTab:AddToggle({Name = "Enable Jump", Default = false, Callback = function(v) states.jump.enabled = v end})

local VisualTab = Window:MakeTab({Name = "Visuals", Icon = "rbxassetid://4483345998"})
VisualTab:AddToggle({Name = "Verified Blue Badge", Default = false, Callback = function(v) states.verified = v end})
VisualTab:AddToggle({Name = "Enable Fake Rank", Default = false, Callback = function(v) states.fakeRank.enabled = v end})
VisualTab:AddDropdown({Name = "Rank Type", Default = "Admin", Options = {"Admin", "Staff", "Creator", "Owner"}, Callback = function(v) states.fakeRank.type = v end})
VisualTab:AddButton({Name = "Summon Fake Player", Callback = function()
    player.Character.Archivable = true
    local c = player.Character:Clone()
    c.Parent = workspace; c:MoveTo(player.Character.Head.Position + Vector3.new(5,0,0))
end})

local ProtectTab = Window:MakeTab({Name = "Protection", Icon = "rbxassetid://4483345998"})
ProtectTab:AddToggle({
    Name = "God Mode (Immune Heart)", 
    Default = false, 
    Callback = function(v) 
        states.godMode = v 
        if v then
            local char = player.Character
            if char and char:FindFirstChild("Humanoid") then
                char.Humanoid.MaxHealth = math.huge
                char.Humanoid.Health = math.huge
            end
        else
            local char = player.Character
            if char and char:FindFirstChild("Humanoid") then
                char.Humanoid.MaxHealth = 100
                char.Humanoid.Health = 100
            end
        end
    end
})
ProtectTab:AddToggle({Name = "Anti-Admin Detector", Default = false, Callback = function(v) states.antiAdmin = v end})
ProtectTab:AddToggle({Name = "Anti-AFK", Default = false, Callback = function(v) states.antiAFK = v end})
ProtectTab:AddSlider({Name = "FPS Limit", Min = 30, Max = 240, Default = 60, Callback = function(v) setfpscap(v) end})
ProtectTab:AddToggle({Name = "Server Auto Lag", Default = false, Callback = function(v) states.autoLag = v end})

local InfoTab = Window:MakeTab({Name = "Community", Icon = "rbxassetid://4483345998"})
InfoTab:AddButton({Name = "Copy Telegram", Callback = function() setclipboard("https://t.me/sxforces") end})
InfoTab:AddButton({Name = "Copy Discord", Callback = function() setclipboard("https://discord.gg/sxforces") end})

rs.Heartbeat:Connect(function()
    if player.Character and player.Character:FindFirstChild("Humanoid") then
        local hum = player.Character.Humanoid
        if states.godMode then
            hum.MaxHealth = math.huge
            hum.Health = math.huge
            if hum.Health <= 0 then
                local oldCF = player.Character.HumanoidRootPart.CFrame
                player:LoadCharacter()
                task.wait(0.1)
                player.Character.HumanoidRootPart.CFrame = oldCF
            end
        end
        if states.speed.enabled then hum.WalkSpeed = states.speed.val end
        if states.jump.enabled then hum.JumpPower = states.jump.val; hum.UseJumpPower = true end
        if states.autoKillAll then
            for _, p in pairs(game.Players:GetPlayers()) do
                if p ~= player and p.Character then p.Character:BreakJoints() end
            end
        end
        if states.autoLag then
            local r = game:GetService("ReplicatedStorage"):FindFirstChildOfClass("RemoteEvent")
            if r then r:FireServer(string.rep("LAG", 100)) end
        end
    end
end)

rs.RenderStepped:Connect(function()
    local char = player.Character
    if char and char:FindFirstChild("Head") then
        if states.fakeRank.enabled or states.verified then
            local head = char.Head
            local bg = head:FindFirstChild("SxR") or Instance.new("BillboardGui", head)
            if bg.Name ~= "SxR" then
                bg.Name = "SxR"; bg.Size = UDim2.new(0, 200, 0, 50); bg.AlwaysOnTop = true; bg.ExtentsOffset = Vector3.new(0, 3, 0)
                local tl = Instance.new("TextLabel", bg)
                tl.BackgroundTransparency = 1; tl.Size = UDim2.new(1, 0, 1, 0); tl.Font = Enum.Font.GothamBold; tl.RichText = true; tl.TextSize = 16
            end
            local rT = states.fakeRank.enabled and "<font color='#FF0000'>["..states.fakeRank.type:upper().."]</font>\n" or ""
            local vT = states.verified and " <font color='#00A2FF'>✔</font>" or ""
            bg.TextLabel.Text = rT .. player.Name .. vT
        end
    end
end)

library:Init()
