rule LockBit_Signature {
    meta:
        description = "Phat hien chu ky chuoi dac trung cua LockBit Ransomware"
        author = "Huynh Tan Dat"
    strings:
        $lockbit1 = "LockBit" ascii wide
        $lockbit2 = ".lockbit" ascii
        $lockbit3 = "All your files have been encrypted by LockBit" ascii wide
    condition:
        2 of them
}

rule Ryuk_Signature {
    meta:
        description = "Phat hien cac chuoi nhan dien cua Ryuk Ransomware"
        author = "Huynh Tan Dat"
    strings:
        $ryuk1 = "RyukReadMe.txt" ascii wide
        $ryuk2 = "HERMES" ascii
        $ryuk3 = "NRYUK" ascii
    condition:
        2 of them
}

rule Ransomware_Anti_Recovery {
    meta:
        description = "Phat hien hanh vi can thiep vao he thong sao luu (VSS)"
        author = "Huynh Tan Dat"
    strings:
        $vss1 = "vssadmin.exe" ascii wide nocase
        $vss2 = "delete shadows" ascii wide nocase
        $vss3 = "wmic shadowcopy delete" ascii wide nocase
        $vss4 = "bcdedit /set {default} recoveryenabled No" ascii wide nocase
    condition:
        ($vss1 and $vss2) or $vss3 or $vss4
}

rule Ransomware_Process_Termination {
    meta:
        description = "Phat hien hanh vi tat cac dich vu va phan mem diet virus"
        author = "Huynh Tan Dat"
    strings:
        $kill1 = "taskkill /f /im" ascii wide nocase
        $kill2 = "net stop \"Volume Shadow Copy\"" ascii wide nocase
        $kill3 = "sc config" ascii wide nocase
    condition:
        2 of them
}

rule WannaCry_Signature {
    meta:
        description = "Phat hien chu ky chuoi nhan dien cua WannaCry Ransomware"
        author = "Huynh Tan Dat"
    strings:
        $str1 = "tasksche.exe" ascii wide
        $str2 = "wnry" ascii wide
        $str3 = "WANA" ascii wide
    condition:
        2 of them
}

rule Generic_Ransomware_Note {
    meta:
        description = "Phat hien cac chuoi van ban doi tien thuong gap"
        author = "Huynh Tan Dat"
    strings:
        $note1 = "All your files have been encrypted" ascii wide
        $note2 = "YOUR_FILES_ARE_LOCKED" ascii wide
        $note3 = "please pay bitcoin" ascii wide
    condition:
        1 of them
}
