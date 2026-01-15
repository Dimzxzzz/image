local library = loadstring(game:HttpGet("https://raw.githubusercontent.com/jensonhirst/Orion/main/source"))()
local Window = library:MakeWindow({
    Name = "Sx-het | Flight Edition",
    HidePremium = false,
    SaveConfig = false,
    IntroEnabled = true,
    IntroText = "Flight System Active",
    Icon = "https://raw.githubusercontent.com/Dimzxzzz/image/refs/heads/main/IMG_20251025_050958_125.jpg"
})

local player = game.Players.LocalPlayer
local char = player.Character or player.CharacterAdded:Wait()
local hum = char:WaitForChild("Humanoid")
local hrp = char:WaitForChild("HumanoidRootPart")
local rs = game:GetService("RunService")

local flying = false
local speed = 50
local bodyGyro, bodyVelocity

local function applyFlightPhysics()
	bodyGyro = Instance.new("BodyGyro", hrp)
	bodyGyro.P = 9e4
	bodyGyro.MaxTorque = Vector3.new(9e9, 9e9, 9e9)
	bodyGyro.CFrame = hrp.CFrame

	bodyVelocity = Instance.new("BodyVelocity", hrp)
	bodyVelocity.MaxForce = Vector3.new(9e9, 9e9, 9e9)
	bodyVelocity.Velocity = Vector3.new(0,0,0)
end

local function startFly()
	if flying then return end
	flying = true
	hum.PlatformStand = true
	if char:FindFirstChild("Animate") then char.Animate.Disabled = true end
	applyFlightPhysics()

	rs:BindToRenderStep("SxFly", Enum.RenderPriority.Character.Value, function()
		if not flying then return end
		local cam = workspace.CurrentCamera
		local moveDir = hum.MoveDirection
		if moveDir.Magnitude > 0 then
			local dir = cam.CFrame:VectorToWorldSpace(moveDir).Unit
			bodyVelocity.Velocity = dir * speed
		else
			bodyVelocity.Velocity = Vector3.new(0,0,0)
		end
		bodyGyro.CFrame = cam.CFrame
	end)
end

local function stopFly()
	if not flying then return end
	flying = false
	rs:UnbindFromRenderStep("SxFly")
	if bodyGyro then bodyGyro:Destroy() end
	if bodyVelocity then bodyVelocity:Destroy() end
	hum.PlatformStand = false
	if char:FindFirstChild("Animate") then char.Animate.Disabled = false end
end

local DashboardTab = Window:MakeTab({Name = "Flight", Icon = "rbxassetid://4483345998"})
DashboardTab:AddSection({Name = "Flight Control System"})
DashboardTab:AddToggle({Name = "Enable Flight", Default = false, Callback = function(state) if state then startFly() else stopFly() end end})
DashboardTab:AddSlider({Name = "Flight Speed", Min = 10, Max = 200, Default = 50, Increment = 1, ValueName = "Speed", Callback = function(v) speed = v end})

local CreditsTab = Window:MakeTab({Name = "Channels", Icon = "rbxassetid://3926305904"})
CreditsTab:AddSection("Official Channels")
CreditsTab:AddButton({Name = "Telegram: t.me/sxheat", Callback = function() setclipboard("t.me/sxheat") end})
CreditsTab:AddButton({Name = "Discord: discord.gg/sxheat", Callback = function() setclipboard("discord.gg/sxheat") end})

local CloseTab = Window:MakeTab({Name = "Close", Icon = "rbxassetid://3926305904"})
CloseTab:AddButton({Name = "Close Sx-het", Callback = function()
    local result = library:MakePrompt({Name = "Are you sure?", Text = "Close flight menu?", Buttons = {"Yes", "Cancel"}})
    if result == "Yes" then library:Destroy() end
end})

local function CreateFloatingLogo()
    local sg = Instance.new("ScreenGui", game.CoreGui)
    sg.Name = "SxMinimizeLogo"
    
    local img = Instance.new("ImageButton", sg)
    img.Size = UDim2.new(0,50,0,50)
    img.Position = UDim2.new(0,10,0,10)
    img.Image = "https://raw.githubusercontent.com/Dimzxzzz/image/refs/heads/main/IMG_20251025_050958_125.jpg"
    img.BackgroundTransparency = 1
    
    local corner = Instance.new("UICorner", img)
    corner.CornerRadius = UDim.new(1,0)
    
    local dragging, dragInput, dragStart, startPos
    img.InputBegan:Connect(function(input)
        if input.UserInputType == Enum.UserInputType.MouseButton1 then
            dragging = true
            dragStart = input.Position
            startPos = img.Position
        end
    end)
    
    img.InputChanged:Connect(function(input)
        if input.UserInputType == Enum.UserInputType.MouseMovement then
            dragInput = input
        end
    end)
    
    game:GetService("UserInputService").InputChanged:Connect(function(input)
        if input == dragInput and dragging then
            local delta = input.Position - dragStart
            img.Position = UDim2.new(startPos.X.Scale, startPos.X.Offset + delta.X, startPos.Y.Scale, startPos.Y.Offset + delta.Y)
        end
    end)
    
    img.InputEnded:Connect(function(input)
        if input.UserInputType == Enum.UserInputType.MouseButton1 then
            dragging = false
        end
    end)

    img.MouseButton1Click:Connect(function()
        pcall(function()
            game:GetService("VirtualInputManager"):SendKeyEvent(true, Enum.KeyCode.RightControl, false, game)
        end)
    end)
end

task.spawn(CreateFloatingLogo)
library:Init()
print("Sx-het Flight System Loaded")
