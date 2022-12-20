	// 검사 후 ajax로 데이터 전송
	function validateEncryptForm() {
		var currentPw = document.getElementById("currentPw").value;
		var password  = document.getElementById("password").value;
		var password2 = document.getElementById("password2").value;
		if (!currentPw || !password || !password2) {
			alert("입력란을 모두 입력해주세요");
			return false;
		}

		if (pwChk() == false) {
			alert("현재 비밀번호가 일치하지 않습니다.");
			currentPw.className = 'form-control bg-light is-invalid mt-3'
			return false;
		}
		if (pw12Chk() == false) {
			alert("새 비밀번호를 확인해주세요.");
			return false;
		}
		
		try {
			var rsaPulbicKeyModulus = document.getElementById("rsaPulbicKeyModulus").value;
			var rsaPulbicKeyExponent = document.getElementById("rsaPulbicKeyExponent").value;
			submitEncryptedForm(password , rsaPulbicKeyModulus , rsaPulbicKeyExponent);
		} catch (err) {
			alert(err);
		}
		return false;
	}
	function submitEncryptedForm(password , rsaPulbicKeyModulus , rsaPulbicKeyExponent) {
		var rsa = new RSAKey();
		rsa.setPublic(rsaPulbicKeyModulus , rsaPulbicKeyExponent);
		var securedPassword = rsa.encrypt(password);
		// 모든 조건을 만족한다면 요청 실행.
		// ajax 요청
		let member = {};
		member.password = securedPassword;
		
		$.ajax({
			type: "post",
			url: "/updatePassword",
			data: member,
			success: function(data) {
				alert('비밀번호 변경 성공');
				console.log(data);
				location.href = data;
			},
			error: function(e) {
				$('#errMsg').html('서버오류');
			}
		});
	}
	// 비밀번호 DB확인 ajax
	function pwChk() {
		var currentPw = document.getElementById("currentPw");
		var result    = document.getElementById("CchkResult");
		var chkresult; 
		if(!currentPw.value) {
			result.innerHTML='현재 비밀번호를 입력해주세요';
			currentPw.className = 'form-control bg-light mt-1 is-invalid';
			return false;
			} else {
				$.ajax({
					url: "/admin/pwCheck",
					type: "post",
					async: false,
					data: {
						password: currentPw.value
					},
					success: function(data) {
						if(data == "0") {
							result.innerHTML='현재 비밀번호가 일치하지 않습니다';
							currentPw.className = 'form-control bg-light mt-1 is-invalid';
							chkresult = false;
						} else if(data == "1"){
							result.innerHTML='현재 비밀번호가 일치합니다';
							currentPw.className = 'form-control bg-light mt-1 is-valid';
							chkresult = true;
						}
						
					},
					error: function() {
						alert("서버요청실패 관리자에게 문의하세요");
						chkresult = false;
					}
				});
			}
		
		
		return chkresult;
	}
	// 비밀번호1,2 확인 function
	function pw12Chk() {
		var pw1 = document.getElementById("password");
		var pw2 = document.getElementById("password2");
		var currentPw = document.getElementById("currentPw");
		var result = document.getElementById("NchkResult");
		var result2 = document.getElementById("NchkResult2");
		if(!pw1.value || !pw2.value) {
			result.innerHTML='새 비밀번호를 입력해주세요';
			pw1.className = "form-control bg-light mt-3 is-invalid";
			pw2.className = "form-control bg-light mt-1 is-invalid";
			return false;
		}
		if(pw1.value == pw2.value && pw1.value == currentPw.value) {
			result2.innerHTML='현재 비밀번호와 새 비밀번호가 같을 수 없습니다.';
			pw1.className = "form-control bg-light mt-3 is-invalid";
			pw2.className = "form-control bg-light mt-1 is-invalid";
			return false;
		} 
		if(pw1.value == pw2.value && pw1.value != currentPw.value) {
			result2.innerHTML='';
			pw1.className       = "form-control bg-light mt-3 is-valid";
			pw2.className       = "form-control bg-light mt-1 is-valid";
			currentPw.className = "form-control bg-light mt-1 is-valid";
		}
		if(pw1.value != null && pw2.value != null && pw1.value == pw2.value) {
			result.innerHTML='새 비밀번호가 일치합니다';
			pw1.className       = "form-control bg-light mt-3 is-valid";
			pw2.className       = "form-control bg-light mt-1 is-valid";
			return true;
		}
		if(pw1.value != null && pw1.value != pw2.value) {
			result.innerHTML='새 비밀번호가 일치하지 않습니다';
			pw1.className = "form-control bg-light mt-3 is-invalid";
			pw2.className = "form-control bg-light mt-1 is-invalid";
			return false;
		}
	}