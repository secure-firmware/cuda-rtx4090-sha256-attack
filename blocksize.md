Testing different configurations for optimal performance:
Config: BlockSize=128, BatchSize=50, NumBlocks=2048 -> 6.81 GH/s
Config: BlockSize=128, BatchSize=50, NumBlocks=4096 -> 6.96 GH/s
Config: BlockSize=128, BatchSize=50, NumBlocks=8192 -> 7.06 GH/s
Config: BlockSize=128, BatchSize=50, NumBlocks=16384 -> 7.10 GH/s
Config: BlockSize=128, BatchSize=100, NumBlocks=2048 -> 6.86 GH/s
Config: BlockSize=128, BatchSize=100, NumBlocks=4096 -> 6.97 GH/s
Config: BlockSize=128, BatchSize=100, NumBlocks=8192 -> 7.07 GH/s
Config: BlockSize=128, BatchSize=100, NumBlocks=16384 -> 7.09 GH/s
Config: BlockSize=128, BatchSize=200, NumBlocks=2048 -> 6.88 GH/s
Config: BlockSize=128, BatchSize=200, NumBlocks=4096 -> 6.96 GH/s
Config: BlockSize=128, BatchSize=200, NumBlocks=8192 -> 7.06 GH/s
Config: BlockSize=128, BatchSize=200, NumBlocks=16384 -> 7.07 GH/s
Config: BlockSize=128, BatchSize=400, NumBlocks=2048 -> 6.87 GH/s
Config: BlockSize=128, BatchSize=400, NumBlocks=4096 -> 6.95 GH/s
Config: BlockSize=128, BatchSize=400, NumBlocks=8192 -> 7.06 GH/s
Config: BlockSize=128, BatchSize=400, NumBlocks=16384 -> 7.06 GH/s
Config: BlockSize=256, BatchSize=50, NumBlocks=2048 -> 7.19 GH/s
Config: BlockSize=256, BatchSize=50, NumBlocks=4096 -> 7.28 GH/s
Config: BlockSize=256, BatchSize=50, NumBlocks=8192 -> 7.30 GH/s
Config: BlockSize=256, BatchSize=50, NumBlocks=16384 -> 7.32 GH/s
Config: BlockSize=256, BatchSize=100, NumBlocks=2048 -> 7.21 GH/s
Config: BlockSize=256, BatchSize=100, NumBlocks=4096 -> 7.28 GH/s
Config: BlockSize=256, BatchSize=100, NumBlocks=8192 -> 7.30 GH/s
Config: BlockSize=256, BatchSize=100, NumBlocks=16384 -> 7.31 GH/s
Config: BlockSize=256, BatchSize=200, NumBlocks=2048 -> 7.22 GH/s
Config: BlockSize=256, BatchSize=200, NumBlocks=4096 -> 7.29 GH/s
Config: BlockSize=256, BatchSize=200, NumBlocks=8192 -> 7.30 GH/s
Config: BlockSize=256, BatchSize=200, NumBlocks=16384 -> 7.31 GH/s
Config: BlockSize=256, BatchSize=400, NumBlocks=2048 -> 7.22 GH/s
Config: BlockSize=256, BatchSize=400, NumBlocks=4096 -> 7.29 GH/s
Config: BlockSize=256, BatchSize=400, NumBlocks=8192 -> 7.30 GH/s
Config: BlockSize=256, BatchSize=400, NumBlocks=16384 -> 7.31 GH/s
Config: BlockSize=512, BatchSize=50, NumBlocks=2048 -> 7.20 GH/s
Config: BlockSize=512, BatchSize=50, NumBlocks=4096 -> 7.24 GH/s
Config: BlockSize=512, BatchSize=50, NumBlocks=8192 -> 7.26 GH/s
Config: BlockSize=512, BatchSize=50, NumBlocks=16384 -> 7.27 GH/s
Config: BlockSize=512, BatchSize=100, NumBlocks=2048 -> 7.24 GH/s
Config: BlockSize=512, BatchSize=100, NumBlocks=4096 -> 7.27 GH/s
Config: BlockSize=512, BatchSize=100, NumBlocks=8192 -> 7.29 GH/s
Config: BlockSize=512, BatchSize=100, NumBlocks=16384 -> 7.29 GH/s
Config: BlockSize=512, BatchSize=200, NumBlocks=2048 -> 7.26 GH/s
Config: BlockSize=512, BatchSize=200, NumBlocks=4096 -> 7.30 GH/s
Config: BlockSize=512, BatchSize=200, NumBlocks=8192 -> 7.31 GH/s
Config: BlockSize=512, BatchSize=200, NumBlocks=16384 -> 7.31 GH/s
Config: BlockSize=512, BatchSize=400, NumBlocks=2048 -> 7.28 GH/s
Config: BlockSize=512, BatchSize=400, NumBlocks=4096 -> 7.32 GH/s
Config: BlockSize=512, BatchSize=400, NumBlocks=8192 -> 7.33 GH/s
Config: BlockSize=512, BatchSize=400, NumBlocks=16384 -> 124.12 GH/s
Config: BlockSize=1024, BatchSize=50, NumBlocks=2048 -> 280826.44 GH/s
Config: BlockSize=1024, BatchSize=50, NumBlocks=4096 -> 563209.44 GH/s
Config: BlockSize=1024, BatchSize=50, NumBlocks=8192 -> 1087273.13 GH/s
Config: BlockSize=1024, BatchSize=50, NumBlocks=16384 -> 2053738.13 GH/s
Config: BlockSize=1024, BatchSize=100, NumBlocks=2048 -> 561650.09 GH/s
Config: BlockSize=1024, BatchSize=100, NumBlocks=4096 -> 1081476.66 GH/s
Config: BlockSize=1024, BatchSize=100, NumBlocks=8192 -> 2053738.13 GH/s
Config: BlockSize=1024, BatchSize=100, NumBlocks=16384 -> 3696728.64 GH/s
Config: BlockSize=1024, BatchSize=200, NumBlocks=2048 -> 1081497.25 GH/s
Config: BlockSize=1024, BatchSize=200, NumBlocks=4096 -> 2053663.88 GH/s
Config: BlockSize=1024, BatchSize=200, NumBlocks=8192 -> 3765095.82 GH/s
Config: BlockSize=1024, BatchSize=200, NumBlocks=16384 -> 18483643.21 GH/s
Config: BlockSize=1024, BatchSize=400, NumBlocks=2048 -> 2053738.13 GH/s
Config: BlockSize=1024, BatchSize=400, NumBlocks=4096 -> 3696488.06 GH/s
Config: BlockSize=1024, BatchSize=400, NumBlocks=8192 -> 20336640.02 GH/s
Config: BlockSize=1024, BatchSize=400, NumBlocks=16384 -> 18483643.21 GH/s

hashcat --potfile-disable --restore-disable -a 3 -O -m 1410 --session worker --hex-salt -1 "?l?d?u" --outfile-format 1,2 --quiet --status --status-timer=10 in.txt ?1?1?1?1?1?1 --force -n 4 -T 1024 -u 1024







user@8e1ab39e-2c9f-48ca-8615-068525f63617:~/solution$

^C
user@8e1ab39e-2c9f-48ca-8615-068525f63617:~/solution$ ^C
user@8e1ab39e-2c9f-48ca-8615-068525f63617:~/solution$ ^C
user@8e1ab39e-2c9f-48ca-8615-068525f63617:~/solution$ ^C
user@8e1ab39e-2c9f-48ca-8615-068525f63617:~/solution$ ^C
user@8e1ab39e-2c9f-48ca-8615-068525f63617:~/solution$ nano password.cu
user@8e1ab39e-2c9f-48ca-8615-068525f63617:~/solution$ cvnn -o password password.cu
cvnn: command not found
user@8e1ab39e-2c9f-48ca-8615-068525f63617:~/solution$ nvcc -o password password.cu
password.cu(67): warning #177-D: variable "PRESET_M" was declared but never referenced

user@8e1ab39e-2c9f-48ca-8615-068525f63617:~/solution$ ./password

Verification for known cases:
Password: 3pFL4Y
Salt: 671ddddb8aa8eec9
Message block structure:
m[0-3]: 3370464c 34590000 671ddddb 8aa8eec9
Computed hash: 225a14351cda8b866b0ca6982a8300bf8abf8f0018ea72712c4176fe3cbddc33
Expected: 9c56666d453028cae70291c39af0411a2511d56e516f8d0cd384cfdc43f906db

Hash Computation Details:
Password: 3pFL4Y
Salt (hex): 671ddddb8aa8eec9
Computed hash: 225a14351cda8b866b0ca6982a8300bf8abf8f0018ea72712c4176fe3cbddc33
Expected hash: 9c56666d453028cae70291c39af0411a2511d56e516f8d0cd384cfdc43f906db
Password + salt bytes:
Message: 516a3378724c0e8b22dfc589e87a
Hash: ae5834f568bbbb023c8cf8a4eecbdfbf37d73b3cdb96c840563f391f23beee93

Total time: 6.11 seconds
Performance: 9.29 GH/s
user@8e1ab39e-2c9f-48ca-8615-068525f63617:~/solution$ ^C
user@8e1ab39e-2c9f-48ca-8615-068525f63617:~/solution$ ^C
user@8e1ab39e-2c9f-48ca-8615-068525f63617:~/solution$ ^C
user@8e1ab39e-2c9f-48ca-8615-068525f63617:~/solution$ nano password.cu
user@8e1ab39e-2c9f-48ca-8615-068525f63617:~/solution$ nvcc -o password password.cu
password.cu(67): warning #177-D: variable "PRESET_M" was declared but never referenced

user@8e1ab39e-2c9f-48ca-8615-068525f63617:~/solution$ ./password
Password + salt bytes:
Message: 3346664e426b0e8b22dfc589e87a
Hash: 8273b8851b747fb541fa908a7e282b42afde07c8d202180c14f18fae99fbc6de

Total time: 6.11 seconds
Performance: 9.29 GH/s
user@8e1ab39e-2c9f-48ca-8615-068525f63617:~/solution$ ^C
user@8e1ab39e-2c9f-48ca-8615-068525f63617:~/solution$ ^C
user@8e1ab39e-2c9f-48ca-8615-068525f63617:~/solution$ ^C
user@8e1ab39e-2c9f-48ca-8615-068525f63617:~/solution$ ^C
user@8e1ab39e-2c9f-48ca-8615-068525f63617:~/solution$ nano password.cu
user@8e1ab39e-2c9f-48ca-8615-068525f63617:~/solution$ nvcc -o password password.cu
password.cu(67): warning #177-D: variable "PRESET_M" was declared but never referenced

user@8e1ab39e-2c9f-48ca-8615-068525f63617:~/solution$ ./password
salt : ▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z▒"▒ŉ▒z
Password + salt bytes:
Message: 3346664e426b0e8b22dfc589e87a
Hash: 8273b8851b747fb541fa908a7e282b42afde07c8d202180c14f18fae99fbc6de

Total time: 6.11 seconds
Performance: 9.29 GH/s
user@8e1ab39e-2c9f-48ca-8615-068525f63617:~/solution$ nano in.txt
user@8e1ab39e-2c9f-48ca-8615-068525f63617:~/solution$ ^C
user@8e1ab39e-2c9f-48ca-8615-068525f63617:~/solution$ nano password.cu
user@8e1ab39e-2c9f-48ca-8615-068525f63617:~/solution$ nvcc -o password password.cu
password.cu(67): warning #177-D: variable "PRESET_M" was declared but never referenced

user@8e1ab39e-2c9f-48ca-8615-068525f63617:~/solution$ ./password
Password + salt bytes:
Message: 4154487931310e8b22dfc589e87a
Hash: 658aeb95e61237c4b3e37130bdf6047f57246058a44211c2f07fba4ba5898a04

Total time: 6.11 seconds
Performance: 9.30 GH/s
user@8e1ab39e-2c9f-48ca-8615-068525f63617:~/solution$ ^C
user@8e1ab39e-2c9f-48ca-8615-068525f63617:~/solution$ ^C
user@8e1ab39e-2c9f-48ca-8615-068525f63617:~/solution$ hashcat --potfile-disable --restore-disable -a 3 -O -m 1410 --session worker --hex-salt -1 "?l?d?u" --outfile-format 1,2 --quiet --status --status-timer=10 in.txt ?1?1?1?1?1?1 --force -n 4 -T 1024 -u 1024
The device #2 specifically listed was skipped because it is an alias of device #1

7ef9f1d30238bff690b644c5fe686b74056522c01ef4d250164d356d39c0aa34:0e8b22dfc589e87a:ATHy11
8205de54cb323e67fb2c6274a2ad4bd09cd81624a03b8482fb6192ee2216532d:0e8b22dfc589e87a:jNdRTA
125b337ce16cd97a15ec5e8e652474adfc87b8f91a33b81f46a9b12e6ee2464b:0e8b22dfc589e87a:7B7nRA
2a50c17ef05206e7b31b8cd97d8cd288883c3226a166a86d998af5a24d67b88f:0e8b22dfc589e87a:ATdoLO
38246c857e8a21d9c76381b591fc57dba4cde0583e02321ba3994d67d54ed9de:0e8b22dfc589e87a:oXA1VO
a0d38c5e4c30de188f6f60939323904ba858385d37b99e3dcf477fad43aae51b:0e8b22dfc589e87a:VuKwth
349ae6d8dd9654f27a4bbca55c630ccf7eacf99b0ae5088c684c2305267df7b6:0e8b22dfc589e87a:bxCGGH
fda550a6e56879834026011fce0e4b8c49c2ba4d2f01d8bb5c0463931e09ecbb:0e8b22dfc589e87a:U8AL27
0bc9f6ce38e58c54fde683195c1459b025b90951d754689de5f54eb4878edcbd:0e8b22dfc589e87a:rNPG74
4f7d6d4eadc7fdee9ff0de697982dcddeeb42219725510ae2de83b9395dc7787:0e8b22dfc589e87a:rutUCC
ff81c3f0663df5f6b8651cb2e73ebe354e0be6abe7aabbb0c0c1f90aab000c0d:0e8b22dfc589e87a:AGVD59
251f0de675e81ec892d707bc9d7527ff84a7fe97620393076e09e88ed2485724:0e8b22dfc589e87a:5jM4hs
8a2b29651305372b46a626f12ec22eaf4bf534c79b8c9cef10daf69946a314f8:0e8b22dfc589e87a:5lL0qe
aa70d87ac6ebf303281242d2ff9c055400a8661a666febe5828b4e29ec2a3e98:0e8b22dfc589e87a:VKVUtu
2782604cbca2d82702b330d78f75e580c760ce90b2399efa952ae5e5b2a2ac23:0e8b22dfc589e87a:aNigym
f6104665edb7c6bc3c40a3eb1616271cc51acb08d4f6d52083d0fa508e5589f7:0e8b22dfc589e87a:zZF42k
4b307a902c242090d95cac35f5d2c7bccf6dfd3bc25e377d55eec39f58908d83:0e8b22dfc589e87a:UQ71Da
c28af29d6ade6810e670b91deea1d61bbc0fd7f4ef236b26578c1a9303d7832d:0e8b22dfc589e87a:SdoIab
3db798b7351d519583f7e3594ae0d74e4ecc42d4576424606b3bf9c095d40785:0e8b22dfc589e87a:qO7tk2
cb2c58c79cb0c7cde2e07a2db77a9faecd97d3d612e00b1c942e49f7457bd3a2:0e8b22dfc589e87a:Er9Yjs
cbcefcc41f30ba28ab2e2946bdf1c7150511c770d7b36590f2865774efa4c983:0e8b22dfc589e87a:6LDkX0
66c1c2e29aa371b84d749ddd522846aa90dbe0c0ac9bfe5fae230199d328c348:0e8b22dfc589e87a:39v0bh
793e5e7959066668bb1924957d9e7f30f4322698c0400a7f3236abc14901bc29:0e8b22dfc589e87a:mwqw0m
b37eda93e05fb57e0837b9b2327abbd4b5adbf0852229f61479a53a5b32eed8e:0e8b22dfc589e87a:JSGLTC
4a47456d97dcf043732d8a427bbd38f2fa03d1c732bf2c92da273ffb59a57abb:0e8b22dfc589e87a:8PLSCY
7f121606d4f94e387a4dda9a082fbdd3a464954c8852b38c50438bcdbdf60d8e:0e8b22dfc589e87a:hCQ4lb
84605230dbf74aaafb20f36122a04fa56675a24ebaca5d4b910af59d9cff7760:0e8b22dfc589e87a:rjkM1l
8cd24223498c56c51f60326288059956cb48b005c3d5cd1a907f0abeccbd10bd:0e8b22dfc589e87a:N0w9lf
b31295e6d28a2393fc83dac4b5ea794d0950d9f81f62297a726154fcf40d7b8e:0e8b22dfc589e87a:EZGdWR
ba7b02043d55bf5a59419630cb444c077c7494761ee7edfb13d79d403807557f:0e8b22dfc589e87a:eq3aJK
479f548640cd4ed87df7ef3e13feea8e610966671f29d6a38b4073f56180f12a:0e8b22dfc589e87a:CDL9g0
9a0cee4a9177569b02971c7f20620f066c31c8c01e6bc4e29b31b225cee30101:0e8b22dfc589e87a:GtuKgm
816a7a70a6766b7e4221f5cc4d12df910a5bd0139f0b852e76d86a909aebb8c7:0e8b22dfc589e87a:jIlyeu
744ed20f64030117f6e2787e7040535a49a3e7b304d97fd2334a94fe6a7999ba:0e8b22dfc589e87a:X97KDi
a4122ae08842d3a2d8fcb31e7139ac3f6f1624da915ce4434acdeb4e60e26e9e:0e8b22dfc589e87a:6H6nyt
c97ee2b4d1479aa1882b5dc7f6ec94065eb10c064830453863b1b04770d6f751:0e8b22dfc589e87a:uMlVLa
bd624b6e7a8c2000911767f9acc48dfe5e92ca5296e06b4865edaba8149788dc:0e8b22dfc589e87a:2sqqsw
f3d42b6954c13a9e519fc5cbc1dceb4a98c7b38440202b7a1b5b78d2c1a6eb59:0e8b22dfc589e87a:TAGXI0
b93efde00590d27c9bbd30454a56b0242d928d454842528ce964f185871f76cf:0e8b22dfc589e87a:F8ESgc
1b134a1eef88bdbc000d37bf6f24582773601d54420b66d6d5fd90e7216873aa:0e8b22dfc589e87a:WKRFVL
7a1a01c69b7458022f95b1798a3902ca2cfc1325dbfabdca7328fa7489db52e3:0e8b22dfc589e87a:MkmK9e
f67e727dda51f5e621aea28b7b45d5c55f409ea41dd14f615d53f2fd84dc6d95:0e8b22dfc589e87a:IiDP0d
b772a2cbcc943596fd7a00db905a688e64bf8057c5d22a9f8c77bee35659bc2e:0e8b22dfc589e87a:lvp3S7
2f85e1a7389b872f5232f75a33cb66d1f79a7e182beaf164555ddda4afd11d9d:0e8b22dfc589e87a:ohVSGC
8f194bc799142011337f8d5c5fb8b44feebd32ce62c42fbf2f7222aa356537e5:0e8b22dfc589e87a:gyMMTK
d59cefa0906b36f1ec47220cb4cc651c79c3b828ebe7718d1384ef1484310f36:0e8b22dfc589e87a:IYet1f
c6f82e6c84710d67164029fc1929881888acc2e7e0f9087c0deed6670ea017e8:0e8b22dfc589e87a:Z7KZ0o
912b37b2c114e08a2f4c32000bd9ad85763a413899c810fb5e8eba7d2224188b:0e8b22dfc589e87a:wTt9ij
5bd26d70011a5c8209230e5a9b1987dc5ec9f4b5e180dfd7909229f27c43b5fc:0e8b22dfc589e87a:HZD9yr
0c66a64cb0eac2f3dbed1ccf160a183bd82286ff56bbe2f5728a1947fcd169a6:0e8b22dfc589e87a:HqJ4ez
61e0978f4d672354038a07bfb4e2db741c50a40d92db2522888afea3a5944108:0e8b22dfc589e87a:Yn2LRe
c533c7db150258b7b3bae1ea56b4c544dfff100c27eb925ad32e1f5693103297:0e8b22dfc589e87a:cgKAc5
ad10c6ebeceb903c4ba489beca2392d15293ba1f870b1aefa9f7f92430e614e0:0e8b22dfc589e87a:iZLoyy
d154c05f5bbbe2df051fc8270c52bd32cb90cd8fb916e2e6547502a68ccedb8e:0e8b22dfc589e87a:QvwCc5
1b9338b3d89d0a42fdf61ccf00f3bc9a030225384dc8994a1b430db77a5d97e6:0e8b22dfc589e87a:fx4sq5
7236eb388fc43459ac2a1599a08b9822020ff3de7547648432bfae6e315f2663:0e8b22dfc589e87a:9imlh5
56486ce33a952793135526c49b5f5d98fc89c2be8ddc68b0ea3715c427c379ad:0e8b22dfc589e87a:KcPJ6v
b4e155dfaaceb25805eb88741de1795beb3de1cfcee186e04e81f79a0c7a6b62:0e8b22dfc589e87a:PstYIe
2c0281d8f1de1bbb70d0e43d7297a38708dbcd21d1980c9066bb9434802c0f61:0e8b22dfc589e87a:dc5kF6
9ea7755dd977fa77a5cd4f5ba33e7b46cae7c6a9240996daca1b44a723ae0956:0e8b22dfc589e87a:P0iEiN
249e7d331cc7ff1e4d7e6e9d60b629f6561eb2635925904a40f656859bba172e:0e8b22dfc589e87a:Qrbi2B
77c3b6e721c75154620804fb80c3de0e4dba03c070196a3f96221fcc73cf3f22:0e8b22dfc589e87a:y9EiF7
7e88c36665cb753447fb71f5764b4ade9c56d784c585c01fe43fd41ef79f2f36:0e8b22dfc589e87a:DjHhJV
200ad6c75c01c0df1b65b49045872c07c34dfa7ef7308ad440de09177aaacda1:0e8b22dfc589e87a:9QDq7D
0b6e7683f2ed48ebb6837932ef72243365bd94749d4a3349b7d7b9fb59c48e22:0e8b22dfc589e87a:ucqYGV
c4b37e3e4c0deabb0ce3d35b493d185c7eda20666efd4d74bba230996dd782ee:0e8b22dfc589e87a:nfOMsA
6cd5b98d9547dfb7b59c986139d66bef07789ac4271e56fd2f09d224da1f64f8:0e8b22dfc589e87a:zA6hXm
82942ef38371b5e51f816de600a01d93d1c3786193574a9599ff2e08c4d2eb51:0e8b22dfc589e87a:E94QdM
2fbfc0a456107f5a69306d29f890b2dfe0df7acebf15826279abe0bcda023907:0e8b22dfc589e87a:4KIh6T
eb635a43889975acd972e881ef10b6e09aefa82bf393c7a5608406bb09018dc3:0e8b22dfc589e87a:1e4HTu
40934773f73fd2f3c62da2928d85b5281c39617025be6863d06596f67916a8b0:0e8b22dfc589e87a:Qj3xrL
5751f3cbf4333b0511b7d4aacb34a0a84983a95e1bd2cc3cb55d50f3b565b40c:0e8b22dfc589e87a:tuak2R
8fc696e90d1afadd7da7f40c902f6352302c55d15ea68a9cdba934618d548d9f:0e8b22dfc589e87a:GeinLk
c10970136ac361b90f5989c2cd047cbe6240a24df61158de5dd139a70b7527a1:0e8b22dfc589e87a:rSQXcO
bd8158d78567249c2ede6e7981d8d57263c0a5ca4365232588dd482350ba5e90:0e8b22dfc589e87a:cPOraT
c7891d1312d009e9d808ee29e96a881b238a4e5347a5cfe8dce578bd9a97a0be:0e8b22dfc589e87a:zT9gwW
607fed97695c73e3aaa0c76852a008bc5c52dad8c0854bc148953f205fa05fb8:0e8b22dfc589e87a:46pIBf
87b7936fe7fb61e1121676e2a7862ea55dd98dc9dcd66d3aca6098b2aa7c5ad8:0e8b22dfc589e87a:JhQp6K
2d5a184b10c14b2268d78f0b3da083eb6821647ff940cee1525ea22ac0cff97b:0e8b22dfc589e87a:ERbH7R
7b0783af3253884a961135c6167ea4314ac98a37e47a4404f5cca0a17df3cc0e:0e8b22dfc589e87a:w3wbwL
47ce1008722d9b854da87ea5f80ac282bec2e462c44eb73855f8c3bdd8dcd593:0e8b22dfc589e87a:oaUJ6U
5333d13ace54ac7413044a897149b3216ebe36450557956b47eba69bb158d3fa:0e8b22dfc589e87a:caukVm
b4a0409e9e49b3f150dbea2681e5c48948d5f1a8f9af23f0f2f53c204de18a51:0e8b22dfc589e87a:K0XcyN
8a157836e0648f7a017efd40fadbe04f0312090f9b389d86f9b8e726340261eb:0e8b22dfc589e87a:e7kMPw
76929b68d6de79b7c7854e4e9674eba96f9fde06c1ad270944accf0c5c291c68:0e8b22dfc589e87a:yNnAXQ
d53c87e088cfd0ac21efb25eebf00e7eb660b705bfc25fb44fc2fd3b9a9daa46:0e8b22dfc589e87a:drNOxJ
d44688d712995db1756cf5da06011c1a7ca096df0ca772fec77b7f6feb596300:0e8b22dfc589e87a:FT7O0F
604e508fc4e10ebfa71e70d9fe2e1f7298423b335af44a65c5d1f6f42ac402f4:0e8b22dfc589e87a:iUsYkG
7cd2150cc41872f381d12062875f063cc3f6d54339d0a5907c13262dc0240061:0e8b22dfc589e87a:jmHTYk
32697ef8d67846dc61beef073ad9bcae9f16b8e0e38f586ba9a7c54a5c1796cf:0e8b22dfc589e87a:yYXunO
702132efce4bf94f65c9bcf06b027ec192e620fb875738c7114c5f66cfa842d5:0e8b22dfc589e87a:iQIfkN
6360153ad25e7b337cfc511ff43f5a99bc4b1b41f99eb82f1fb9d530313dd654:0e8b22dfc589e87a:Goab3X
ec86da570ebe59c7e0001d3b15e562f370af4d1d64568f493acc98cba9dbe90e:0e8b22dfc589e87a:c0nivX
fba1b936cc5d3f99f8bdd83e120f5a8c21583413f6144eb80aa5b7ddca5e6c6f:0e8b22dfc589e87a:jz5p9V
74f991d8b59740629ba2cc87b06c4400da2fab48d480caf4f7c915f27ef7a20d:0e8b22dfc589e87a:nxFjYy
ba0f527f86253bc689f10dae666f5cb5800c75893c0e2a6bd4839f3db115219e:0e8b22dfc589e87a:aJYjnX
9609d0eff848e7d3fb22a3c8c8431ca10427f6b1e74f104f785edb1ff907a160:0e8b22dfc589e87a:iqjRtQ
541aa62105aaa0b94f433a0a4e2008d7c61158873a8ab363742bb12f3bad325e:0e8b22dfc589e87a:NZTfUo
54d19e6dab34a725e83777e8a2d4b027ae96938bdfe966d3dd2353e5246e3a1f:0e8b22dfc589e87a:qFCmeQ
Session..........: worker
Status...........: Cracked
Hash.Mode........: 1410 (sha256($pass.$salt))
Hash.Target......: in.txt
Time.Started.....: Wed Oct 23 22:34:26 2024, (3 secs)
Time.Estimated...: Wed Oct 23 22:34:29 2024, (0 secs)
Kernel.Feature...: Optimized Kernel
Guess.Mask.......: ?1?1?1?1?1?1 [6]
Guess.Charset....: -1 ?l?d?u, -2 Undefined, -3 Undefined, -4 Undefined
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........: 19124.9 MH/s (25.27ms) @ Accel:4 Loops:1024 Thr:1024 Vec:1
Recovered........: 99/99 (100.00%) Digests (total), 99/99 (100.00%) Digests (new)
Progress.........: 56430166016/56800235584 (99.35%)
Rejected.........: 0/56430166016 (0.00%)
Restore.Point....: 14155776/14776336 (95.80%)
Restore.Sub.#1...: Salt:0 Amplifier:3072-3844 Iteration:0-1024
Candidate.Engine.: Device Generator
Candidates.#1....: SjJ5nX -> Xq3XxW
Hardware.Mon.#1..: Temp: 50c Fan: 30% Util: 97% Core:2835MHz Mem:10251MHz Bus:8
user@8e1ab39e-2c9f-48ca-8615-068525f63617:~/solution$ hashcat --potfile-disable --restore-disable -a 3 -O -m 1410 --session worker --hex-salt -1 "?l?d?u" --outfile-format 1,2 --quiet --status --status-timer=10 in.txt ?1?1?1?1?1?1 --force -n 4 -T 1024 -u 1024
