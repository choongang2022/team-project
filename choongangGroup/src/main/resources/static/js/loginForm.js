	function validateEncryptForm() {
		var keepLogin = 0;
		var username = document.getElementById("username").value;
		var password = document.getElementById("password").value;
		if (!username || !password) {
			alert("아이디 또는 비밀번호를 입력해주세요");
			return false;
		}
		// 자동로그인 확인창 및 keepLogin 값 세팅
		if($("#keepLogin").is(':checked')) {
			if(!confirm("2주 동안 로그인이 유지됩니다.\n일반 로그인보다 보안에 취약할 수 있습니다.\n자동로그인 하시겠습니까?")) {
				return false;
			} else {
				keepLogin = 1;
			}
			
		}
		// 로그인 요청 ajax 포함된 함수 호출 submitEncryptedForm
		try {
			var rsaPulbicKeyModulus = document.getElementById("rsaPulbicKeyModulus").value;
			var rsaPulbicKeyExponent = document.getElementById("rsaPulbicKeyExponent").value;
			submitEncryptedForm(username , password , rsaPulbicKeyModulus , rsaPulbicKeyExponent, keepLogin);
		} catch (err) {
			alert(err);
		}
		return false;
	}
	
	// 로그인 요청 ajax
	function submitEncryptedForm(username , password , rsaPulbicKeyModulus , rsaPulbicKeyExponent, keepLogin) {
		var rsa = new RSAKey();
		rsa.setPublic(rsaPulbicKeyModulus , rsaPulbicKeyExponent);
	
		var securedUsername = rsa.encrypt(username);
		var securedPassword = rsa.encrypt(password);

		$.ajax({
			type: "post",
			url: "/login",
			data: {securedUsername:securedUsername,
				   securedPassword:securedPassword,
				   keepLogin:keepLogin},
			//contentType: "json",
			success: function(data) {
				if(keepLogin == 0) {
					alert("로그인 성공\n접속 후 1시간동안 페이지 이동이 없으면\n자동으로 로그아웃됩니다");
				} else if(keepLogin == 1) {
					alert("로그인 성공\n로그인 상태는 2주동안 유지됩니다.");
				}
				console.log("로그인 성공");
				console.log(data);
				location.href = data;
			},
			error: function(e) {
				$('#errMsg').html('아이디가 존재하지 않거나 비밀번호가 틀렸습니다.');
			}
		})
	}