	function validateEncryptForm() {
		var username = document.getElementById("username").value;
		var password = document.getElementById("password").value;
		var name     = document.getElementById("name").value;
		if (!username || !password || !name) {
			alert("아이디, 비밀번호, 성명을 모두 입력해주세요");
			return false;
		}

		if (idChk() == false) {
			alert("아이디 중복");
			return false;
		}
		if (pwChk() == false) {
			alert("비밀번호 불일치");
			return false;
		}
		
		try {
			var rsaPulbicKeyModulus = document.getElementById("rsaPulbicKeyModulus").value;
			var rsaPulbicKeyExponent = document.getElementById("rsaPulbicKeyExponent").value;
			submitEncryptedForm(username , password , rsaPulbicKeyModulus , rsaPulbicKeyExponent);
		} catch (err) {
			alert(err);
		}
		return false;
	}
	function submitEncryptedForm(username , password , rsaPulbicKeyModulus , rsaPulbicKeyExponent) {
		var rsa = new RSAKey();
		rsa.setPublic(rsaPulbicKeyModulus , rsaPulbicKeyExponent);
	
		var securedUsername = rsa.encrypt(username);
		var securedPassword = rsa.encrypt(password);
		
		// 모든 조건을 만족한다면 생성 요청 실행.
		// ajax 생성 요청
		let member = {};
		member.userid   = securedUsername;
		member.password = securedPassword;
		member.name     = document.getElementById("name").value;
		member.memRole  = $('#role option:selected').val();
		
		$.ajax({
			type: "post",
			url: "/admin/createMember",
			data: member,
			success: function(data) {
				alert('아이디 생성 성공');
				console.log(data);
				location.href = data;
			},
			error: function(e) {
				$('#errMsg').html('생성오류');
			}
		});
	}
	
	//아이디 check ajax
	function idChk() {
		var username = document.getElementById("username").value;
		var result   = document.getElementById("idChkResult");
		var chkresult; 
		if(!username) {
			result.innerHTML='아이디를 입력해주세요';
			document.getElementById("username").className = 'form-control bg-light is-invalid mt-3'
			return false;
			}
		
		$.ajax({
			url: "/admin/idCheck",
			type: "post",
			async: false,
			data: {
				userid: username
			},
			success: function(data) {
				if(data == "0") {
					result.innerHTML='사용할 수 없는 아이디입니다.';
					document.getElementById("username").className = 'form-control bg-light is-invalid mt-3'
					chkresult = false;
				} else if(data == "1"){
					result.innerHTML='사용할 수 있는 아이디입니다.';
					document.getElementById("username").className = 'form-control bg-light is-valid mt-3'
					chkresult = true;
				}
				
			},
			error: function() {
				alert("서버요청실패 관리자에게 문의하세요");
				chkresult = false;
			}
		});
		return chkresult;
	}
	
	// 비밀번호 check
	function pwChk() {
		var pw1 = document.getElementById("password").value;
		var pw2 = document.getElementById("password2").value;
		var result = document.getElementById("passwordChkDiv");
		if(!pw1 || !pw2) {
			result.innerHTML='비밀번호를 입력해주세요';
			document.getElementById("password").className = 'form-control bg-light is-invalid mt-3';
			document.getElementById("password2").className = 'form-control bg-light is-invalid mt-1';
			return false;
		}
		if(pw1 != null && pw1 != pw2) {
			result.innerHTML='비밀번호가 일치하지 않습니다';
			document.getElementById("password").className = 'form-control bg-light is-invalid mt-3';
			document.getElementById("password2").className = 'form-control bg-light is-invalid mt-1';
			return false;
		} 
		if(pw1 != null && pw2 != null && pw1 == pw2) {
			result.innerHTML='비밀번호가 일치합니다';
			document.getElementById("password").className = 'form-control bg-light is-valid mt-3';
			document.getElementById("password2").className = 'form-control bg-light is-valid mt-1';
			return true;
		}
	}
	
	function nameChk() {
		var name = document.getElementById("name").value;
		var result = document.getElementById("nameChkDiv");
		if(!name) {
			result.innerHTML='성명을 입력해주세요';
			document.getElementById("name").className = 'form-control bg-light is-invalid';
			return false;
		} else {
			result.innerHTML='';
			document.getElementById("name").className = 'form-control bg-light is-valid';
			return true;
		}
	}
	
	// 유저별 추가정보 div 추가
	/*function changeRole() {
		var roleSelect = $('#role option:selected').val();
		var roleAdd = $('#roleAdd')
		if (roleSelect == 'ROLE_STUDENT') {
			roleAdd.html("<div>학생정보</div>");
		}
		else if (roleSelect == 'ROLE_MANAGER') {
			roleAdd.html("<div>교직원정보</div>");
		}
		else if (roleSelect == 'ROLE_PROFESSOR') {
			roleAdd.html("<div>교수정보</div>");
		}
		else if (roleSelect == 'ROLE_ADMIN') {
			roleAdd.html("<div>관리자정보</div>");
		}
	}*/