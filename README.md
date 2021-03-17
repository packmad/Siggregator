## SIGGREGATOR ~ SIGnature agGREGATOR

Even if this project's name is one of the worst ever, Siggregator could be very useful.

In *malware analysis*, we often have to categorize many binary samples based on static signatures.

In my humble experience, I noticed that the best signatures are those of:

1. The evergreen [libmagic](https://man7.org/linux/man-pages/man3/libmagic.3.html) library

2. [Detect-It-Easy](https://github.com/horsicq/Detect-It-Easy)

3. [Yara](https://virustotal.github.io/yara/) signatures of [Retdec](https://github.com/avast/retdec/tree/master/support/yara_patterns/tools)

However, the approaches and use cases are totally different.
First of all, `libmagic` just recognizes file types based on magic numbers, so no packers, compilers, installers, protectors, etc.
Detect-It-Easy (DIE) uses finely tuned signatures bases on a dedicated scripting language (and therefore a dedicated engine), 
while Retdec provides well-maintained Yara signatures.
DIE is very accurate but slow, and its database lacks some rules, while Yara is very fast and has a vast database but prone to false positives.
Moreover, they use different technologies, which are sometimes tedious to configure on different operating systems.

Siggregator was born to be used as a [Docker](https://www.docker.com/) container à la build&run plug&play minimum-effort&maximum-result, 
to compare the output of the tools mentioned above.

```
git clone https://github.com/packmad/Siggregator.git
cd Siggregator
docker build . -t packmad:siggregator
./siggregator.sh IN_DIR OUT_FILE
```

* `IN_DIR` - is the input directory that contains the files to be analyzed
* `OUT_FILE` - will be a json file containing the output of those tools


### How it works in a nutshell

In order to minimize false positives, 
and given the fact that Retdec's signatures are organized into fileformat/architecture:

1. Fast check by inspecting the first bytes of the files (MZ, .ELF, ...), non-executable files are not analysed
2. Precise file type and architecture identification from libmagic
3. Scan with the proper Yara rules for such file type/architecture
4. DIE scan
5. Output pre-processing


### JSON is cool, but I would like to aggregate everything in a CSV

Of course! Have a look at [results_to_csv.py](https://github.com/packmad/Siggregator/blob/master/siggregator/results_to_csv.py), 
it has been written in pure Python3 (i.e., no dependencies), you do not need Docker BUT be careful: 
the script is mixing DIE with Yara, removing versions, etc. it is likely that you need to fix the code for your use case.

Usage:
```
./results_to_csv.py input.json output.csv
```

Moreover, if a cell has multiple values, they are joined in alphabetical order using the semicolon as a separator, 
for example: 
```
# cat example.csv
SHA256,FILE_FORMAT,ARCH_BITS,ENDIANESS,COMPILER,LINKER,LIBRARY,PACKER/PROTECTOR,INSTALLER,SFX/ARCHIVE,OVERLAY,OTHER
verylongsha256,pe,32,LE,aut2exe;msvc,microsoft linker,autoit,,,,,
```
It means that the detected compilers are `aut2exe` and `msvc`.



### Example with two files

1. [37bea5b0a24fa6fed0b1649189a998a0e51650dd640531fe78b6db6a196917a7](https://www.virustotal.com/gui/file/37bea5b0a24fa6fed0b1649189a998a0e51650dd640531fe78b6db6a196917a7/detection)
2. [d7e1d13cab1bd8be1f00afbec993176cc116c2b233209ea6bd33e6a9b1ec7a7f](https://www.virustotal.com/gui/file/d7e1d13cab1bd8be1f00afbec993176cc116c2b233209ea6bd33e6a9b1ec7a7f/detection)

```
# ./siggregator.sh /tmp/twoviruses /tmp/twoviruses.json
> Scanning input directory...
> Found 2 files. Analysis in progress...
100%|██████████| 2/2 [00:01<00:00, 32.76it/s]
> Analysis done!
> Found 2 executable files. Writing output file...
> "out.json" written. Bye!
```
```
# cat /tmp/out.json | jq
[
   {
      "sha256":"37bea5b0a24fa6fed0b1649189a998a0e51650dd640531fe78b6db6a196917a7",
      "magic":"PE32 executable (GUI) Intel 80386, for MS Windows",
      "format":"pe",
      "arch":"x86",
      "die":{
         "arch":"I386",
         "detects":[
            {
               "name":"VMProtect",
               "options":null,
               "type":"protector",
               "version":null
            },
            {
               "name":"Microsoft Visual C/C++",
               "options":null,
               "type":"compiler",
               "version":"2017 v.15.6"
            },
            {
               "name":"Microsoft Linker",
               "options":"GUI32",
               "type":"linker",
               "version":"14.13, Visual Studio 2017 15.6*"
            }
         ],
         "endianess":"LE",
         "filetype":"PE32",
         "mode":"32",
         "type":"GUI"
      },
      "yara":[
         {
            "type":"packer",
            "rule":"vmprotect_2x_xx",
            "name":"VMProtect",
            "version":"2.04+"
         }
      ]
   },
   {
      "sha256":"d7e1d13cab1bd8be1f00afbec993176cc116c2b233209ea6bd33e6a9b1ec7a7f",
      "magic":"PE32 executable (GUI) Intel 80386, for MS Windows",
      "format":"pe",
      "arch":"x86",
      "die":{
         "arch":"I386",
         "detects":[
            {
               "name":"WinRAR",
               "options":null,
               "type":"sfx",
               "version":null
            },
            {
               "name":"Microsoft Visual C/C++",
               "options":null,
               "type":"compiler",
               "version":"2015 v.14.0"
            },
            {
               "name":"Microsoft Linker",
               "options":"GUI32,admin",
               "type":"linker",
               "version":"14.0, Visual Studio 2015 14.0*"
            },
            {
               "name":"RAR archive",
               "options":null,
               "type":"overlay",
               "version":null
            },
            {
               "name":"RAR",
               "options":"57.2%,2 files",
               "type":"archive",
               "version":"4"
            }
         ],
         "endianess":"LE",
         "filetype":"PE32",
         "mode":"32",
         "type":"GUI"
      },
      "yara":[
         {
            "type":"installer",
            "rule":"winrar_sfx_540",
            "name":"WinRAR SFX",
            "version":"5.40"
         }
      ]
   }
]
```

```
# ./results_to_csv.py /tmp/twoviruses.json /tmp/twoviruses.csv
> Input json file contains 2 elements
> "/tmp/twoviruses.csv" written. Bye!

# cat /tmp/twoviruses.csv
SHA256,FILE_FORMAT,ARCH_BITS,ENDIANESS,COMPILER,LINKER,LIBRARY,PACKER/PROTECTOR,INSTALLER,SFX/ARCHIVE,OVERLAY,OTHER
37...a7,pe,32,LE,msvc,microsoft linker,,vmprotect,,,,
d7...7f,pe,32,LE,msvc,microsoft linker,,,winrar sfx,rar,rar archive,
```