import ftplib

path = ''
filename = 'ffmpeg_build.zip'

ftp = ftplib.FTP("192.168.1.152") 
ftp.login("ocrClient", "Lms@2024") 
ftp.cwd(path)
ftp.retrbinary("RETR " + filename, open(filename, 'wb').write)
ftp.quit()

