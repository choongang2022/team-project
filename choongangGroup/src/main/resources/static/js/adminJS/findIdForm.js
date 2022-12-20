	function findId() {
		var name = document.getElementById('name').value;
		var email = document.getElementById('email').value;
		var resultdiv = document.getElementById('findIdResult');
		
		if (validateValues() == false) {
			return false;
		} else {
			let member = {};
			member.name = name;
			member.email = email;
			
			$.ajax({
				type: "post",
				url: "/anonymous/findId",
				data: member,
				success: function(data) {
					alert('조회성공');
					console.log(data);
					resultdiv.innerHTML = '아이디는 ' + data + ' 입니다.';
					
				},
				error: function(error) {
					alert("조건에 맞는 아이디가 없거나 서버오류");
					$('#errMsg').html('조건에 맞는 아이디가 없거나 서버오류');
				}
			});
		}
		
		
	}
	
	function validateValues() {
		var name = document.getElementById('name').value;
		var email = document.getElementById('email').value;
		
		if (!name) {
			alert("이름을 입력해주세요")
			return false;
		}
		
		if (!email) {
			alert("이메일을 입력해주세요")
			return false;
		}
	}