0. sudo apt-get update -qq && sudo apt-get -y install \
  autoconf \
  automake \
  build-essential \
  cmake \
  git-core \
  libfreetype6-dev \
  libgnutls28-dev \
  libmp3lame-dev \
  libsdl2-dev \
  libtool \
  libva-dev \
  libvdpau-dev \
  libvorbis-dev \
  libxcb1-dev \
  libxcb-shm0-dev \
  libxcb-xfixes0-dev \
  meson \
  ninja-build \
  pkg-config \
  texinfo \
  wget \
  yasm \
  zlib1g-dev
sudo apt install libunistring-dev libaom-dev libdav1d-dev libsrt-dev
sudo apt-get install libsdl2-dev
   apt-get install libopus-dev
   sudo apt-get install libx264-dev
   sudo apt-get install libass-dev (bao loi)
1、首先编译metartc相关包

    # cmake_x64会自动创建build文件夹

    cd ffmpeg-webrtc/FFmpeg-n4.3.3/metartc6

    cd /metartc6/libmetartccore6
   
    ./cmake_x64.sh
    
    # 把编译成功的 libmetartccore6.a 复制到metartc6文件夹下
    cp build/libmetartccore6.a ~/ffmpeg-webrtc-orginal/FFmpeg-n4.3.3/metartc6

    # Requires ffmpeg to be configured with --enable-gpl --enable-libx264
    

2、解压libsrtp-2-fit.tar.gz、openssl-1.1-fit.tar.gz并进行编译

    cd ffmpeg-webrtc/FFmpeg-n4.3.3/metartc6
    
    # 编译 srtp2
    tar zxvf libsrtp-2-fit.tar.gz
    cd libsrtp-2-fit/
    ./configure 
    make
    cp libsrtp2.a ~/ffmpeg-webrtc-orginal/FFmpeg-n4.3.3/metartc6
    
    # 编译openssl
    tar zxvf openssl-1.1-fit.tar.gz
    cd openssl-1.1-fit/
    ./config
    make
    cp libcrypto.a libssl.a ~/ffmpeg-webrtc-orginal/FFmpeg-n4.3.3/metartc6

    wget https://www.openssl.org/source/openssl-3.1.0.tar.gz

    sudo tar -xf openssl-3.1.0.tar.gz

    cd openssl-3.1.0

    sudo ./config --prefix=/usr/local/ssl --openssldir=/usr/local/ssl shared zlib

    sudo make && sudo make install
        
3、编译FFmpeg-webrtc    

   
    ./configure --enable-libx264 --enable-gpl --enable-cross-compile --enable-libpulse --enable-libopus --enable-ffplay --disable-shared --enable-static --extra-cflags='--static' --pkg-config-flags="--static" --enable-libsrt --enable-nonfree --enable-libass --enable-libfreetype --enable-libmp3lame --enable-openssl --extra-libs='-L/home/tungnh/test/ffmpeg-webrtc/FFmpeg-n4.3.3/metartc6 -lmetartccore6 -lpthread -lsrtp2 -lssl -lcrypto -ldl' --extra-ldflags=-ldl 
    make -j8
    # 编译期间会报很多错误，可以不用理会
    make install

4、目前测试结果

    1）ffplay 没有，可能是少包了，或者编译FFmpeg-webrtc时./configure中没有启用相关配置
    2）使用whip推流到SRS流媒体服务器，但是拉流失败！目前暂未找到原因
    
    3）把RTMP流推送到SRS，SRS把RTMP转成RTC，使用FFmpeg-webrtc whep拉流，成功实现延迟1秒左右
# opus 配置
    sudo apt-get install libopus-dev
    
# 编译FFmpeg-Webrtc
    ./configure --enable-libx264 --enable-gpl --enable-cross-compile --enable-libpulse --enable-libopus --enable-ffplay --extra-libs='-L/home/oook/user/ffmpeg-webrtc/FFmpeg-n4.3.3/metartc6 -lmetartccore6 -lpthread -lsrtp2 -lssl -lcrypto -ldl'

# ffplay 播放命令
    ffplay -i 'webrtc://127.0.0.1:1985/rtc/v1/whip-play/?app=live&stream=livestream'
# SRS的whep地址是：http://127.0.0.1:1985/rtc/v1/whep/?app=live&stream=livestream
ffmpeg -i 'webrtc://127.0.0.1:1985/rtc/v1/whep/?app=live&stream=livestream' -vcodec rawvideo -pix_fmt yuv420p -f v4l2 /dev/video30
ffmpeg -i 'webrtc://127.0.0.1:1985/rtc/v1/whip-play/?app=live&stream=livestream' -vcodec rawvideo -pix_fmt yuv420p -f v4l2 /dev/video30

./ffmpeg -re -i ffmpeg-webrtc/test.mp4 -vcodec libx264 -acodec opus -strict -2 -ar 48000 -f webrtc "http://192.168..1.23:1853/rtc/v1/whip/?app=live&stream=livestream12345"




# 推流命令 WHIP
ffmpeg ......-acodec opus -strict -2 -ar 48000 -f webrtc "url"  
srs sample: whip url http://192.168.0.105:1985/rtc/v1/whip/?app=live&stream=livestream  
ffmpeg ......-acodec opus -strict -2 -ar 48000 -f webrtc "http://192.168.0.105:1985/rtc/v1/whip/?app=live&stream=livestream"  
ffmpeg ......-acodec opus -strict -2 -ar 48000 -f webrtc "webrtc://192.168.0.105:1985/rtc/v1/whip/?app=live&stream=livestream"  
./ffmpeg -re -i /path/test.mp4 -vcodec libx264 -acodec opus -strict -2 -ar 48000 -f webrtc "http://192.168.0.105:1985/rtc/v1/whip/?app=live&stream=livestream"


# 拉流命令 WHEP
ffplay "webrtc://whep_url"  
srs sample: whep url http://192.168.0.105:1985/rtc/v1/whip-play/?app=live&stream=livestream  
ffplay "webrtc://192.168.0.105:1985/rtc/v1/whip-play/?app=live&stream=livestream"  




