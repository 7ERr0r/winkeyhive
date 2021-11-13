winkeyhive
===

Prebuilt binary:
```
curl https://github.com/7ERr0r/winkeyhive/releases/download/v0.1/winkeyhive_amd64 -L -o winkeyhive && chmod 755 winkeyhive && ./winkeyhive
```


To retrieve Windows product keys on Ubuntu:
`cargo run`

displays:
```
Hive path:      /media/ubuntu/D05A69D89047438D/Windows/System32/config/SOFTWARE
ProductName:    Windows 10 Home
ProductID:      00151-80000-00000-AABET
Win10 Key:      7HNRX-D7KGG-3K1CQ-4WPJ4-YDDFH
Win8 Key:       VK2JG-NPHEM-C97JM-8CPGT-3V76T

Hive path:      /media/ubuntu/483D01EC7BB9490D/Windows/System32/config/SOFTWARE
ProductName:    Windows 10 Home N
ProductID:      00481-20000-00001-AA012
Win10 Key:      3KEY7-WBR83-DGQKR-F7HER-842BM
Win8 Key:       YNNXQ-8RYV3-4P2Q3-C8XTP-7CFAY
```

Didn't work? Make sure target drives are mounted:
```
mount | grep /dev/sd
```

Still not working?
```
cargo run /mnt/your_drive/Windows/System32/config/SOFTWARE
```
