local library = loadstring(game:HttpGet("https://raw.githubusercontent.com/jensonhirst/Orion/main/source"))()
local Window = library:MakeWindow({
    Name = "Sx-het",
    HidePremium = false,
    SaveConfig = false
})

local flyBodyVelocity
local function toggleFly(state)
    if state then
        flyActive = true
        flyBodyVelocity = Instance.new("BodyVelocity")
        flyBodyVelocity.Velocity = Vector3.new(0,0,0)
        flyBodyVelocity.MaxForce = Vector3.new(40000,40000,40000)
        flyBodyVelocity.Parent = character.HumanoidRootPart
        
        rs.Heartbeat:Connect(function()
            if flyActive and character and character.HumanoidRootPart then
                local cf = character.HumanoidRootPart.CFrame
                local move = Vector3.new(0,0,0)
                
                if uis:IsKeyDown(Enum.KeyCode.W) then move = move + (cf.LookVector * 50) end
                if uis:IsKeyDown(Enum.KeyCode.S) then move = move - (cf.LookVector * 50) end
                if uis:IsKeyDown(Enum.KeyCode.A) then move = move - (cf.RightVector * 50) end
                if uis:IsKeyDown(Enum.KeyCode.D) then move = move + (cf.RightVector * 50) end
                if uis:IsKeyDown(Enum.KeyCode.Space) then move = move + Vector3.new(0,50,0) end
                if uis:IsKeyDown(Enum.KeyCode.LeftControl) then move = move - Vector3.new(0,50,0) end
                
                flyBodyVelocity.Velocity = move
            end
        end)
    else
        flyActive = false
        if flyBodyVelocity then flyBodyVelocity:Destroy() end
    end
end

local speedActive = false
local function toggleSpeed(state)
    if state then
        speedActive = true
        humanoid.WalkSpeed = 100
    else
        speedActive = false
        humanoid.WalkSpeed = 16
    end
end

local jumpActive = false
local function toggleJump(state)
    if state then
        jumpActive = true
        humanoid.JumpPower = 150
    else
        jumpActive = false
        humanoid.JumpPower = 50
    end
end

local secretActive = false
local function autoSecretFish(state)
    secretActive = state
    while secretActive do
        task.wait(math.random(2,5))
        pcall(function()
            local remote = game:GetService("ReplicatedStorage"):FindFirstChild("CatchFish")
            if remote then remote:FireServer("Legendary", math.random(100,1000)) end
        end)
    end
end

local rodActive = false
local function autoFishingRod(state)
    rodActive = state
    while rodActive do
        task.wait(0.8)
        pcall(function()
            local cast = game:GetService("ReplicatedStorage"):FindFirstChild("CastRod")
            if cast then cast:FireServer() end
            task.wait(1.2)
            local reel = game:GetService("ReplicatedStorage"):FindFirstChild("ReelFish")
            if reel then reel:FireServer() end
        end)
    end
end

local coinsActive = false
local function unlimitedCoins(state)
    coinsActive = state
    while coinsActive do
        task.wait(0.2)
        pcall(function()
            local events = {"AddCoins","AddMoney","AddCurrency","GetReward","ClaimReward"}
            for _, eventName in ipairs(events) do
                local event = game:GetService("ReplicatedStorage"):FindFirstChild(eventName)
                if event then event:FireServer(9999) end
            end
        end)
    end
end

local antiStaffActive = false
local bannedKeywords = {"[developer]","[admin]","[creator]","[development]","[staff]","[moderator]","[owner]","[founder]"}
local function toggleAntiStaff(state)
    antiStaffActive = state
    if state then
        for _, plr in ipairs(game:GetService("Players"):GetPlayers()) do
            if plr ~= player then
                local nameLower = plr.Name:lower()
                local displayLower = plr.DisplayName:lower()
                for _, keyword in ipairs(bannedKeywords) do
                    if string.find(nameLower, keyword:lower()) or string.find(displayLower, keyword:lower()) then
                        pcall(function()
                            game:GetService("ReplicatedStorage"):FindFirstChild("ReportPlayer"):FireServer(plr.Name, "Staff Detected")
                        end)
                        break
                    end
                end
            end
        end
        game:GetService("Players").PlayerAdded:Connect(function(newPlayer)
            if antiStaffActive then
                task.wait(1)
                local nameLower = newPlayer.Name:lower()
                local displayLower = newPlayer.DisplayName:lower()
                for _, keyword in ipairs(bannedKeywords) do
                    if string.find(nameLower, keyword:lower()) or string.find(displayLower, keyword:lower()) then
                        pcall(function()
                            local kickRemote = game:GetService("ReplicatedStorage"):FindFirstChild("KickPlayer")
                            if kickRemote then
                                kickRemote:FireServer(newPlayer.Name)
                            else
                                game:GetService("ReplicatedStorage"):FindFirstChild("ReportPlayer"):FireServer(newPlayer.Name, "Staff Detected")
                            end
                        end)
                        break
                    end
                end
            end
        end)
    end
end

local fpsActive = false
local function toggleFPS(state)
    fpsActive = state
    if state then
        settings().Rendering.QualityLevel = 1
        settings().Rendering.MeshPartDetailLevel = Enum.MeshPartDetailLevel.Level04
        game:GetService("Lighting").GlobalShadows = false
        game:GetService("Lighting").FogEnd = 100000
        for _, effect in ipairs(game:GetService("Lighting"):GetChildren()) do
            if effect:IsA("PostEffect") or effect:IsA("BloomEffect") or effect:IsA("BlurEffect") then
                effect.Enabled = false
            end
        end
        rs.RenderStepped:Connect(function()
            if fpsActive then
                game:GetService("Stats").Workspace.MemoryStats:GetTotalMemoryUsageMb()
            end
        end)
    end
end

local lagActive = false
local function toggleLagReducer(state)
    lagActive = state
    if state then
        for _, part in ipairs(workspace:GetDescendants()) do
            if part:IsA("ParticleEmitter") then part.Rate = 0 end
        end
        game:GetService("Players").LocalPlayer.MaximumSimulationRadius = 50
    end
end

local DashboardTab = Window:MakeTab({Name = "Dashboard", Icon = "rbxassetid://3926305904"})
DashboardTab:AddSection("Special Features")
DashboardTab:AddToggle({Name = "Fly (WASD + Space/Ctrl)", Default = false, Callback = toggleFly})
DashboardTab:AddToggle({Name = "Run Fast (100 Speed)", Default = false, Callback = toggleSpeed})
DashboardTab:AddToggle({Name = "High Jump (150 Power)", Default = false, Callback = toggleJump})

local FishingTab = Window:MakeTab({Name = "Fish It", Icon = "rbxassetid://3926307971"})
FishingTab:AddSection("Auto Fishing")
FishingTab:AddToggle({Name = "Auto Secret Fish", Default = false, Callback = autoSecretFish})
FishingTab:AddToggle({Name = "Auto Fishing Rod", Default = false, Callback = autoFishingRod})
FishingTab:AddToggle({Name = "Unlimited Coins", Default = false, Callback = unlimitedCoins})

local SettingsTab = Window:MakeTab({Name = "Settings", Icon = "rbxassetid://3926307971"})
SettingsTab:AddSection("Protection")
SettingsTab:AddToggle({Name = "Anti Staff (Auto Ban)", Default = false, Callback = toggleAntiStaff})
SettingsTab:AddSection("Performance")
SettingsTab:AddToggle({Name = "FPS Stabilizer (120+ FPS)", Default = false, Callback = toggleFPS})
SettingsTab:AddToggle({Name = "Reduce Lag", Default = false, Callback = toggleLagReducer})

local CreditsTab = Window:MakeTab({Name = "Channels", Icon = "rbxassetid://3926305904"})
CreditsTab:AddSection("Official Channels")
CreditsTab:AddButton({Name = "Telegram: t.me/sxheat", Callback = function() setclipboard("t.me/sxheat") end})
CreditsTab:AddButton({Name = "Discord: discord.gg/sxheat", Callback = function() setclipboard("discord.gg/sxheat") end})
CreditsTab:AddParagraph("Disclaimer", "Use at your own risk.")

local CloseTab = Window:MakeTab({Name = "Close", Icon = "rbxassetid://3926305904"})
CloseTab:AddButton({Name = "Close Sx-het", Callback = function()
    local result = library:MakePrompt({Name = "Are you sure?", Text = "Do you want to close Sx-het cheat menu?", Buttons = {"Yes", "Cancel"}})
    if result == "Yes" then library:Destroy() end
end})

game:GetService("Players").LocalPlayer.CharacterAdded:Connect(function(newChar)
    character = newChar
    humanoid = character:WaitForChild("Humanoid")
end)

print("Sx-het Loaded")
