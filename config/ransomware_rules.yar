rule WannaCry_Signature {
    meta:
        description = "Phat hien chu ky chuoi nhan dien cua WannaCry Ransomware"
        author = "Huynh Tan Dat"
    strings:
        $str1 = "tasksche.exe" ascii
        $str2 = "wnry" ascii
        $str3 = "WANA"
    condition:
        2 of them
}

rule Generic_Ransomware_Note {
    meta:
        description = "Phat hien cac chuoi van ban doi tien thuong gap"
        author = "Huynh Tan Dat"
    strings:
        $note1 = "All your files have been encrypted" ascii
        $note2 = "YOUR_FILES_ARE_LOCKED" ascii
        $note3 = "please pay bitcoin" ascii
    condition:
        1 of them
}