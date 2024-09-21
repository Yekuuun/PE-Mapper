```

                                 ____  ______     __  ___                           
                                / __ \/ ____/    /  |/  /___ _____  ____  ___  _____
                               / /_/ / __/______/ /|_/ / __ `/ __ \/ __ \/ _ \/ ___/
                              / ____/ /__/_____/ /  / / /_/ / /_/ / /_/ /  __/ /    
                             /_/   /_____/    /_/  /_/\__,_/ .___/ .___/\___/_/     
                                                          /_/   /_/                 

                                -------A base x32 & x64 PE file mapper------    

```

**Manually map PE into memory & display informations.**

This repository was created due to my interest for windows internals & learning about malwares who often are related to PE files. The main purpose here is to learn who to pick a PE file & manually mapping it into memory learning manipulating RVA addresses & complex structures of a PE.

---

### Supports :
- Mapping from disk
- Relocations
- Loaded imports
- Mapping sections
- x86 & x64 architecture

![PEMAPPER](https://github.com/Yekuuun/PE-Mapper/blob/main/assets/pe-mapper.png)

---

### Building

- clone project : `https://github.com/Yekuuun/PE-Mapper.git`
- go to `/mapper` & create build dir `mkdir build`
- go to `/build` & run `cmake ..`
- build with `cmake --build .`
- run program using `./pe-mapper <path_to_pe_file>`

---

### Thanks to : 

[MALWARE_TRAINING_VOL1](https://github.com/hasherezade/malware_training_vol1) <br> <br>
[MANUAL_DLL_LOADER](https://github.com/adamhlt/Manual-DLL-Loader)


