## Windows 설정
1. 관리자 권한으로 powershell 실행.
2. Get-ExecutionPolicy
3. Set-ExecutionPolicy RemoteSigned
4. wsl2.ps1 실행

## WSL 설정
1. cat /etc/resolv.conf
2. netsh interface portproxy add v4tov4 listenport=15000 listenaddress=0.0.0.0 connectport=15000 connectaddress=주소
3. netsh interface portproxy show v4tov4
