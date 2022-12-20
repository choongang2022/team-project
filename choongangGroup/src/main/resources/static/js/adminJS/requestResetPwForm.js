	//이메일 전송 ajax
		function sendEmail() {
			
			//checkIdEmail();
			if (checkIdEmail() == false) {
				return false;
			} else {
				var userid = document.getElementById("userid");
				var email  = document.getElementById("email");
				var emailResult  = document.getElementById("emailResult");
				emailResult.innerHTML = '<div class="spinner-border" role="status">' +
										'<span class="visually-hidden">Loading...</span> ' +
										'</div>'
				
				let member = {};
				member.userid = userid.value;
				member.email  = email.value;
				
				$.ajax({
					type: "GET",
					url: "/anonymous/sendEmail",
					data: member,
					success: function() {
						alert('메일 전송 성공');
						emailResult.innerHTML = '임시비밀번호가 메일로 발송되었습니다.<br> 임시비밀번호로 로그인하여 비밀번호를 변경해주세요.';
					},
					error: function(e) {
						alert(e);
					}
				});
			}
		}
		
		//아이디 이메일 DB check ajax
		function checkIdEmail() {
			var userid = document.getElementById("userid");
			var email  = document.getElementById("email");
			var chkresult; 
			if(!userid || !email) {
				alert("입력란을 모두 입력해주세요");
				chkresult = false;
			}
			else {
				// userid email check
				let member = {};
				member.userid = userid.value;
				member.email  = email.value;
				$.ajax({
					url: "/anonymous/idEmailCheck",
					type: "post",
					async: false,
					data: member,
					success: function(data) {
						if(data == "0") {
							alert("일치하는 정보가 존재하지 않습니다");
							chkresult = false;
						} 
						if(data == "1"){
							alert("정보가 일치합니다")
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