# MHW-HashLogger
A small plugin for Monster Hunter: World that hooks the game's CRC-32/JAMCRC and (inverted)CRC-32/ISCSI functions and logs unique hashes to disk.

## Installation & Usage
(Requires [Strackeror](https://github.com/Strackeror)'s [MHW plugin loader](https://www.nexusmods.com/monsterhunterworld/mods/1982))

1. Copy the latest release build `.dll` into the `{GAMEFOLDER}/NativePC/plugins` folder, or build yourself per the instruction below.
2. (Optional) Copy the existing `hash_log.txt` from this repo into your `{GAMEFOLDER}`.
3. Run the game and play, it will output unique hashes to the `{GAMEFOLDER}/hash_log.txt` file. This file is loaded and appened to on game restart, no need to back it up between runs.


## Building
1. Clone with `git clone --recurse-submodules -j8 git://github.com/Andoryuuta/MHW-HashLogger.git`
2. Open with Visual Studio 2019 via the "Open Folder" option (for cmake), and build with x64 clang.

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License
[MIT](https://choosealicense.com/licenses/mit/)