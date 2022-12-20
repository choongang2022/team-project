<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>
<head>
	<meta charset="UTF-8">
	<title>title</title>
<!-- bootStrap CSS only -->
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.2/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-Zenh87qX5JnK2Jl0vWa8Ck2rdkQ2Bzep5IDxbcnCeuOxjzrPF/et3URy9Bv1WTRi" crossorigin="anonymous">		
<!-- bootStrap Icons -->
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.9.1/font/bootstrap-icons.css">
<!-- JavaScript Bundle with Popper -->
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.2/dist/js/bootstrap.bundle.min.js" integrity="sha384-OERcA2EqjJCMA+/3y+gxIOqMEjwtxJY7qPCqsdltbNJuaOe923+mo//f6V8Qbsw3" crossorigin="anonymous"></script>
<!-- jQuery -->
<script src="http://code.jquery.com/jquery-latest.min.js"></script>
<!-- font awesome -->
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.2.0/css/all.min.css" integrity="sha512-xh6O/CkQoPOWDdYTDqeRdPCVd1SpvCA9XXcUnZS2FmJNp1coAFzvtCN9BmamE+4aHK8yyUHUSCcJHgXloTyT2A==" crossorigin="anonymous" referrerpolicy="no-referrer" />
<!-- RSA JS -->
<script src="/js/jsbn.js" type="text/javascript"></script>
<script src="/js/rsa.js" type="text/javascript"></script>
<script src="/js/prng4.js" type="text/javascript"></script>
<script src="/js/rng.js" type="text/javascript"></script>
<!-- This Page JS -->
<script src="/js/adminJS/createMemberForm.js" type="text/javascript"></script>
</head>

<style type="text/css">
	html, body {
		height: 100%;
	}
	body {
		background-color: rgb(214, 225, 237);
	}
	.container {
		max-width: 420px;
	}
</style>
<body>
        <!-- Role별 추가 정보 -->
        <!-- <div id="roleAdd">
        	<div>학생정보</div>
        </div> -->
	<main class="container position-absolute top-50 start-50 translate-middle form-signin w-100 m-auto text-center">
		<h1 class="mb-5 fw-bold">계정생성</h1>
		<div class="form-floating">
   			<select class="form-select" id="role" onchange="changeRole()" aria-label="Floating label select example">
				<option value="ROLE_STUDENT">학생</option>
            	<option value="ROLE_MANAGER">교직원</option>
	            <option value="ROLE_PROFESSOR">교수</option>
	            <option value="ROLE_ADMIN">관리자</option>
			</select>
    		<label for="role">회원구분</label>
		</div>
	    <div class="form-floating">
	    	<input type="text" class="form-control bg-light mt-3" id="username" aria-describedby="idChkResult" onfocusout="idChk()">
	    	<label for="floatingInput">아이디</label>
	    	<small id="idChkResult" class="text-muted">
     			
    		</small>
	    </div>
	    <div class="form-floating">
	    	<input type="password" class="form-control bg-light mt-3" id="password">
	    	<label for="floatingPassword">비밀번호</label>
	    </div>
	    <div class="form-floating">
	    	<input type="password" class="form-control bg-light mt-1" id="password2" aria-describedby="passwordChkDiv" onfocusout="pwChk()">
	    	<label for="floatingPassword">비밀번호확인</label>
	    	<small id="passwordChkDiv" class="text-muted">
     			
    		</small>
	    	
	    </div>
	    <div class="form-floating">
	    	<input type="text" class="form-control bg-light mt-3" id="name" onfocusout="nameChk()">
	    	<label for="floatingInput">성명</label>
	    	<small id="nameChkDiv" class="text-muted">
     			
    		</small>
	    </div>
	    <!-- errMsg -->
	    <div class="h6 mb-3 fw-normal" id="errMsg"></div>
		<!-- login button -->
	    <button class="w-100 btn btn-lg btn-primary mb-3" type="button" onclick="validateEncryptForm();">계정생성</button>
		<button class="w-100 btn btn-lg btn-primary mb-3 mt-1" type="button" onclick="location.href='/'">메인페이지</button>
	    
	</main>
    <!-- hidden values -->
    <input type="hidden" id="rsaPulbicKeyModulus" value="${publicKeyModulus}">
	<input type="hidden" id="rsaPulbicKeyExponent" value="${publicKeyExponent}">
</body>
</html>