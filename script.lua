local library = loadstring(game:HttpGet("https://raw.githubusercontent.com/jensonhirst/Orion/main/source"))()
local Window = library:MakeWindow({
    Name = "Sx-het | Premium Edition",
    HidePremium = false,
    SaveConfig = true,
    ConfigFolder = "SxHetConfig",
    IntroEnabled = true,
    IntroText = "Welcome, Yang Mulia Skyy",
    Icon = "https://raw.githubusercontent.com/Dimzxzzz/image/refs/heads/main/IMG_20251025_050958_125.jpg"
})

local player = game.Players.LocalPlayer
local char = player.Character or player.CharacterAdded:Wait()
local hum = char:WaitForChild("Humanoid")
local hrp = char:WaitForChild("HumanoidRootPart")
local rs = game:GetService("RunService")
local uis = game:GetService("UserInputService")

local states = {
    speed = {enabled = false, val = 16},
    jump = {enabled = false, val = 50},
    fly = {enabled = false, val = 50},
    lockPos = {enabled = false, pos = nil}
}

local function updateAbilities()
    rs.Heartbeat:Connect(function()
        if states.speed.enabled then hum.WalkSpeed = states.speed.val else hum.WalkSpeed = 16 end
        if states.jump.enabled then hum.JumpPower = states.jump.val else hum.JumpPower = 50 end
        
        if states.lockPos.enabled and hrp then
            if not states.lockPos.pos then states.lockPos.pos = hrp.CFrame end
            hrp.CFrame = states.lockPos.pos
            hrp.Velocity = Vector3.new(0,0,0)
        end
    end)
end

local bodyGyro, bodyVelocity
local function toggleFly(state)
    states.fly.enabled = state
    if state then
        hum.PlatformStand = true
        bodyGyro = Instance.new("BodyGyro", hrp)
        bodyGyro.P = 9e4
        bodyGyro.MaxTorque = Vector3.new(9e9, 9e9, 9e9)
        bodyVelocity = Instance.new("BodyVelocity", hrp)
        bodyVelocity.MaxForce = Vector3.new(9e9, 9e9, 9e9)

        task.spawn(function()
            while states.fly.enabled do
                local cam = workspace.CurrentCamera
                local moveDir = hum.MoveDirection
                bodyVelocity.Velocity = (moveDir.Magnitude > 0) and (cam.CFrame:VectorToWorldSpace(moveDir).Unit * states.fly.val) or Vector3.new(0,0,0)
                bodyGyro.CFrame = cam.CFrame
                task.wait()
            end
            if bodyGyro then bodyGyro:Destroy() end
            if bodyVelocity then bodyVelocity:Destroy() end
            hum.PlatformStand = false
        end)
    end
end

local MainTab = Window:MakeTab({Name = "Settings", Icon = "rbxassetid://4483345998"})

MainTab:AddSection({Name = "Player Utility"})

MainTab:AddTextbox({
    Name = "Custom Speed Value",
    Default = "100",
    TextDisappear = false,
    Callback = function(v) states.speed.val = tonumber(v) or 16 end
})
MainTab:AddToggle({
    Name = "Enable Sprint",
    Default = false,
    Callback = function(v) states.speed.enabled = v end
})

MainTab:AddTextbox({
    Name = "Custom Jump Value",
    Default = "150",
    TextDisappear = false,
    Callback = function(v) states.jump.val = tonumber(v) or 50 end
})
MainTab:AddToggle({
    Name = "Enable Infinite Jump",
    Default = false,
    Callback = function(v) states.jump.enabled = v end
})

local MovementTab = Window:MakeTab({Name = "Movement", Icon = "rbxassetid://4483362458"})

MovementTab:AddSection({Name = "Aerial & Position"})

MovementTab:AddSlider({
    Name = "Fly Speed",
    Min = 10, Max = 300, Default = 50,
    Color = Color3.fromRGB(255,150,0),
    Increment = 1, ValueName = "SPS",
    Callback = function(v) states.fly.val = v end
})

MovementTab:AddToggle({
    Name = "Enable Fly",
    Default = false,
    Callback = toggleFly
})

MovementTab:AddToggle({
    Name = "Lock Position (Freeze)",
    Default = false,
    Callback = function(v) 
        states.lockPos.enabled = v 
        states.lockPos.pos = v and hrp.CFrame or nil
    end
})

local function CreateFloatingLogo()
    local sg = Instance.new("ScreenGui", game.CoreGui)
    sg.Name = "SxPremiumLogo"
    
    local img = Instance.new("ImageButton", sg)
    img.Size = UDim2.new(0, 55, 0, 55)
    img.Position = UDim2.new(0, 20, 0, 20)
    img.Image = "https://raw.githubusercontent.com/Dimzxzzz/image/refs/heads/main/IMG_20251025_050958_125.jpg"
    img.BackgroundTransparency = 1
    img.ZIndex = 10
    
    local corner = Instance.new("UICorner", img)
    corner.CornerRadius = UDim.new(1, 0)
    
    local stroke = Instance.new("UIStroke", img)
    stroke.Color = Color3.fromRGB(255, 165, 0)
    stroke.Thickness = 2

    local dragging, dragInput, dragStart, startPos
    img.InputBegan:Connect(function(input)
        if input.UserInputType == Enum.UserInputType.MouseButton1 then
            dragging = true
            dragStart = input.Position
            startPos = img.Position
        end
    end)

    img.InputChanged:Connect(function(input)
        if input.UserInputType == Enum.UserInputType.MouseMovement then dragInput = input end
    end)

    uis.InputChanged:Connect(function(input)
        if input == dragInput and dragging then
            local delta = input.Position - dragStart
            img.Position = UDim2.new(startPos.X.Scale, startPos.X.Offset + delta.X, startPos.Y.Scale, startPos.Y.Offset + delta.Y)
        end
    end)

    img.InputEnded:Connect(function(input)
        if input.UserInputType == Enum.UserInputType.MouseButton1 then dragging = false end
    end)

    img.MouseButton1Click:Connect(function()
        pcall(function()
            game:GetService("VirtualInputManager"):SendKeyEvent(true, Enum.KeyCode.RightControl, false, game)
        end)
    end)
end

updateAbilities()
task.spawn(CreateFloatingLogo)
library:Init()
