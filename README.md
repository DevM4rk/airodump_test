### 개요

airodump-ng와 똑같은 출력을 할 수 있는 프로그램.


### 실행

```
syntax : airodump <interface>
sample : airodump mon0
```


### 상세


- Beacon Frame에서 BSSID, Beacons, (#Data), (ENC), ESSID 출력.


- Beacon Frame에서 PWR 정보는 Radiotap Header에 있음.


- Station은 기본적으로 AP와 연결되어 통신을 하지만 그렇지 않은 Frame(Probe Request)도 존재함.


- Channel Hopping 기능을 추가.


- 가상의 무선 네트워크 어댑터를 생성 기법을 이용하여 편하게 디버깅.


- GitHub airodump-ng 소스 코드 참조함.
