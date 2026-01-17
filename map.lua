local library = loadstring(game:HttpGet("https://raw.githubusercontent.com/jensonhirst/Orion/main/source"))()

local Window = library:MakeWindow({
    Name = "Sx-Forces | Map Stealer Premium",
    HidePremium = false,
    SaveConfig = true,
    ConfigFolder = "SxForcesMap",
    IntroEnabled = true,
    IntroText = "Akses Premium: Mulia Dimzxzzx07",
    Icon = "rbxassetid://6031068433"
})

library.Theme = {
    Default = Color3.fromRGB(80, 0, 150),
    WindowList = Color3.fromRGB(30, 0, 50),
    Tabs = Color3.fromRGB(50, 0, 100),
    TabSecondary = Color3.fromRGB(150, 50, 255),
    Section = Color3.fromRGB(60, 0, 110),
    TextColor = Color3.fromRGB(255, 255, 255)
}

local StealerTab = Window:MakeTab({Name = "Map Stealer", Icon = "rbxassetid://4483345998"})

StealerTab:AddButton({
    Name = "Get All Map Scripts (Decompile)",
    Callback = function()
        library:MakeNotification({
            Name = "Proses Dimulai",
            Content = "Sedang mengambil seluruh kode map... Harap tunggu.",
            Image = "rbxassetid://4483345998",
            Time = 5
        })
        
        local scriptCount = 0
        local fullCode = "-- Map Code Dump by Sx-Forces --\n"
        fullCode = fullCode .. "-- Game ID: " .. game.PlaceId .. "\n"
        fullCode = fullCode .. "-- Diminta oleh: Mulia Dimzxzzx07 --\n\n"

        for _, v in pairs(game:GetDescendants()) do
            if v:IsA("LocalScript") or v:IsA("ModuleScript") then
                scriptCount = scriptCount + 1
                fullCode = fullCode .. "-- Script Path: " .. v:GetFullName() .. "\n"
                fullCode = fullCode .. "-- Source:\n" .. (v.Source or "-- Source Not Accessible --") .. "\n\n"
            end
        end

        setclipboard(fullCode)
        
        library:MakeNotification({
            Name = "Berhasil!",
            Content = "Berhasil mengambil " .. scriptCount .. " skrip. Kode telah disalin ke clipboard.",
            Image = "rbxassetid://4483345998",
            Time = 5
        })
    end
})

StealerTab:AddButton({
    Name = "Save Game (Full Map Data)",
    Callback = function()
        if saveinstance then
            library:MakeNotification({
                Name = "Saving...",
                Content = "Sedang menyimpan seluruh data map ke folder workspace executor Anda.",
                Image = "rbxassetid://4483345998",
                Time = 10
            })
            saveinstance()
        else
            library:MakeNotification({
                Name = "Error",
                Content = "Executor Anda tidak mendukung fungsi saveinstance().",
                Image = "rbxassetid://4483345998",
                Time = 5
            })
        end
    end
})

local InfoTab = Window:MakeTab({Name = "Channel", Icon = "rbxassetid://4483345998"})
InfoTab:AddParagraph("Developer", "@Dimzxzzx07")
InfoTab:AddLabel("Script: sx-forces Map Stealer")
InfoTab:AddLabel("Version: 2.0 Premium")
InfoTab:AddButton({ Name = "Telegram", Callback = function() setclipboard("https://t.me/sxforces") end })
InfoTab:AddButton({ Name = "Discord", Callback = function() setclipboard("https://discord.gg/sxforces") end })
InfoTab:AddLabel("Copyright 2026")

library:Init()
