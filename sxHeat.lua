local library = loadstring(game:HttpGet("https://raw.githubusercontent.com/jensonhirst/Orion/main/source"))()
local Window = library:MakeWindow({
    Name = "Sx-het | @Dimzxzzx07",
    HidePremium = false,
    SaveConfig = true,
    ConfigFolder = "SxHetConfig",
    IntroEnabled = true,
    IntroText = "Welcome, To SxHeat",
    Icon = "https://raw.githubusercontent.com/Dimzxzzz/image/refs/heads/main/IMG_20251025_050958_125.jpg"
})

local player = game.Players.LocalPlayer
local rs = game:GetService("RunService")
local uis = game:GetService("UserInputService")
local lp = game:GetService("Lighting")

local states = {
    speed = {enabled = false, val = 100},
    jump = {enabled = false, val = 150},
    fly = {enabled = false, val = 50},
    lockPos = {enabled = false, pos = nil},
    antiAFK = false,
    fpsBooster = false,
    disableEffects = false,
    fakeRank = {enabled = false, type = "Admin"},
    fakeLevel = {enabled = false, val = "999"}
}

player.Idled:Connect(function()
    if states.antiAFK then
        game:GetService("VirtualUser"):Button2Down(Vector2.new(0,0), workspace.CurrentCamera.CFrame)
        task.wait(1)
        game:GetService("VirtualUser"):Button2Up(Vector2.new(0,0), workspace.CurrentCamera.CFrame)
    end
end)

local function createFakeRank()
    rs.RenderStepped:Connect(function()
        local char = player.Character
        if char and char:FindFirstChild("Head") then
            if states.fakeRank.enabled or states.fakeLevel.enabled then
                local head = char.Head
                local bgui = head:FindFirstChild("SxRankLabel") or Instance.new("BillboardGui", head)
                if bgui.Name ~= "SxRankLabel" then
                    bgui.Name = "SxRankLabel"
                    bgui.Size = UDim2.new(0, 200, 0, 50)
                    bgui.AlwaysOnTop = true
                    bgui.ExtentsOffset = Vector3.new(0, 3, 0)
                    local tl = Instance.new("TextLabel", bgui)
                    tl.BackgroundTransparency = 1
                    tl.Size = UDim2.new(1, 0, 1, 0)
                    tl.Font = Enum.Font.GothamBold
                    tl.TextSize = 14
                    tl.TextColor3 = Color3.fromRGB(255, 0, 0)
                    tl.TextStrokeTransparency = 0
                end
                local rankTxt = states.fakeRank.enabled and "["..states.fakeRank.type.."] " or ""
                local lvlTxt = states.fakeLevel.enabled and " | Lvl: "..states.fakeLevel.val or ""
                bgui.TextLabel.Text = rankTxt .. player.Name .. lvlTxt
            else
                if char.Head:FindFirstChild("SxRankLabel") then char.Head.SxRankLabel:Destroy() end
            end
        end
    end)
end

local function toggleFPS(state)
    lp.GlobalShadows = not state
    if state then
        for _, v in pairs(game:GetDescendants()) do
            if v:IsA("Part") or v:IsA("MeshPart") then
                v.Material = Enum.Material.SmoothPlastic
            end
        end
    end
end

local function toggleEffects(state)
    states.disableEffects = state
    for _, v in pairs(game:GetDescendants()) do
        if v:IsA("ParticleEmitter") or v:IsA("Smoke") or v:IsA("Fire") or v:IsA("Sparkles") or v:IsA("Explosion") then
            v.Enabled = not state
        end
    end
end

rs.Heartbeat:Connect(function()
    local char = player.Character
    if char then
        local hum = char:FindFirstChildOfClass("Humanoid")
        local hrp = char:FindFirstChild("HumanoidRootPart")
        if hum then
            hum.UseJumpPower = true
            if states.speed.enabled then
                hum.WalkSpeed = states.speed.val
            else
                hum.WalkSpeed = 16
            end
            if states.jump.enabled then
                hum.JumpPower = states.jump.val
            else
                hum.JumpPower = 50
            end
        end
        if states.lockPos.enabled and hrp and states.lockPos.pos then
            hrp.CFrame = states.lockPos.pos
            hrp.Velocity = Vector3.new(0,0,0)
        end
    end
end)

local SettingsTab = Window:MakeTab({Name = "Settings", Icon = "rbxassetid://4483345998"})
SettingsTab:AddSection({Name = "Player Utility"})
SettingsTab:AddTextbox({
    Name = "Sprint Speed", Default = "100", TextDisappear = false,
    Callback = function(v) states.speed.val = tonumber(v) or 16 end
})
SettingsTab:AddToggle({
    Name = "Enable Sprint", Default = false,
    Callback = function(v) states.speed.enabled = v end
})
SettingsTab:AddTextbox({
    Name = "Jump Power", Default = "150", TextDisappear = false,
    Callback = function(v) states.jump.val = tonumber(v) or 50 end
})
SettingsTab:AddToggle({
    Name = "Enable Jump Mod", Default = false,
    Callback = function(v) states.jump.enabled = v end
})

local SystemTab = Window:MakeTab({Name = "System", Icon = "rbxassetid://4483345998"})
SystemTab:AddSection({Name = "Protection"})
SystemTab:AddToggle({Name = "Anti-AFK", Default = false, Callback = function(v) states.antiAFK = v end})
SystemTab:AddSection({Name = "Performance"})
SystemTab:AddToggle({Name = "FPS Booster", Default = false, Callback = function(v) toggleFPS(v) end})
SystemTab:AddToggle({Name = "Disable All Large Effects", Default = false, Callback = function(v) toggleEffects(v) end})

local VisualTab = Window:MakeTab({Name = "Visuals", Icon = "rbxassetid://4483345998"})
VisualTab:AddSection({Name = "Fake Identity"})
VisualTab:AddDropdown({
    Name = "Choose Rank", Default = "Admin", Options = {"Admin", "Creator", "Developer", "Development"},
    Callback = function(v) states.fakeRank.type = v end    
})
VisualTab:AddToggle({Name = "Enable Fake Rank", Default = false, Callback = function(v) states.fakeRank.enabled = v end})
VisualTab:AddTextbox({Name = "Fake Level Value", Default = "999", TextDisappear = false, Callback = function(v) states.fakeLevel.val = v end})
VisualTab:AddToggle({Name = "Enable Fake Level", Default = false, Callback = function(v) states.fakeLevel.enabled = v end})

local MovementTab = Window:MakeTab({Name = "Movement", Icon = "rbxassetid://4483362458"})
MovementTab:AddSection({Name = "Advanced Flight"})
MovementTab:AddSlider({
    Name = "Fly Speed", Min = 10, Max = 500, Default = 50, Color = Color3.fromRGB(255,165,0),
    Increment = 1, ValueName = "SPS", Callback = function(v) states.fly.val = v end
})
MovementTab:AddToggle({
    Name = "Enable Fly", Default = false,
    Callback = function(state)
        states.fly.enabled = state
        local char = player.Character
        local hrp = char and char:FindFirstChild("HumanoidRootPart")
        if state and hrp then
            local bg = Instance.new("BodyGyro", hrp)
            local bv = Instance.new("BodyVelocity", hrp)
            bg.P = 9e4; bg.MaxTorque = Vector3.new(9e9, 9e9, 9e9)
            bv.MaxForce = Vector3.new(9e9, 9e9, 9e9)
            task.spawn(function()
                while states.fly.enabled do
                    local cam = workspace.CurrentCamera
                    bv.Velocity = (char.Humanoid.MoveDirection.Magnitude > 0) and (cam.CFrame:VectorToWorldSpace(char.Humanoid.MoveDirection).Unit * states.fly.val) or Vector3.new(0,0,0)
                    bg.CFrame = cam.CFrame
                    task.wait()
                end
                bg:Destroy(); bv:Destroy()
            end)
        end
    end
})
MovementTab:AddToggle({
    Name = "Lock Position (Freeze)", Default = false,
    Callback = function(v) 
        states.lockPos.enabled = v 
        if v and player.Character then states.lockPos.pos = player.Character.HumanoidRootPart.CFrame else states.lockPos.pos = nil end
    end
})

local AboutTab = Window:MakeTab({Name = "About", Icon = "rbxassetid://4483345998"})
AboutTab:AddSection({Name = "Script Information"})
AboutTab:AddParagraph("Version","1.0.0 Ultimate Premium")
AboutTab:AddParagraph("Developer","SkyyXploit")
AboutTab:AddButton({
    Name = "Telegram Channel",
    Callback = function()
        setclipboard("https://t.me/sxheat")
        library:MakeNotification({Name = "Copied", Content = "Telegram link copied to clipboard!", Time = 3})
    end
})

local function CreateFloatingLogo()
    local sg = Instance.new("ScreenGui", game.CoreGui)
    local img = Instance.new("ImageButton", sg)
    img.Size = UDim2.new(0, 55, 0, 55)
    img.Position = UDim2.new(0, 100, 0, 100)
    img.Image = "https://raw.githubusercontent.com/Dimzxzzz/image/refs/heads/main/IMG_20251025_050958_125.jpg"
    img.BackgroundTransparency = 1
    Instance.new("UICorner", img).CornerRadius = UDim.new(1, 0)
    local strk = Instance.new("UIStroke", img)
    strk.Color = Color3.fromRGB(255, 165, 0); strk.Thickness = 2
    local dragging, dragInput, dragStart, startPos
    img.InputBegan:Connect(function(input)
        if input.UserInputType == Enum.UserInputType.MouseButton1 then
            dragging = true; dragStart = input.Position; startPos = img.Position
        end
    end)
    uis.InputChanged:Connect(function(input)
        if dragging and input.UserInputType == Enum.UserInputType.MouseMovement then
            local delta = input.Position - dragStart
            img.Position = UDim2.new(startPos.X.Scale, startPos.X.Offset + delta.X, startPos.Y.Scale, startPos.Y.Offset + delta.Y)
        end
    end)
    img.InputEnded:Connect(function(input) if input.UserInputType == Enum.UserInputType.MouseButton1 then dragging = false end end)
    img.MouseButton1Click:Connect(function()
        game:GetService("VirtualInputManager"):SendKeyEvent(true, Enum.KeyCode.RightControl, false, game)
    end)
end

createFakeRank()
task.spawn(CreateFloatingLogo)
library:Init()
