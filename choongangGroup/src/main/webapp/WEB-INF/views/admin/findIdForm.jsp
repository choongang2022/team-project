<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Insert title here</title>
<!-- bootStrap CSS only -->
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.2/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-Zenh87qX5JnK2Jl0vWa8Ck2rdkQ2Bzep5IDxbcnCeuOxjzrPF/et3URy9Bv1WTRi" crossorigin="anonymous">		
<!-- bootStrap Icons -->
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.9.1/font/bootstrap-icons.css">
<!-- JavaScript Bundle with Popper -->
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.2/dist/js/bootstrap.bundle.min.js" integrity="sha384-OERcA2EqjJCMA+/3y+gxIOqMEjwtxJY7qPCqsdltbNJuaOe923+mo//f6V8Qbsw3" crossorigin="anonymous"></script>
<!-- jQuery -->
<script src="http://code.jquery.com/jquery-latest.min.js"></script>
<!-- font awesome -->
<link rel="styles
heet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.2.0/css/all.min.css" integrity="sha512-xh6O/CkQoPOWDdYTDqeRdPCVd1SpvCA9XXcUnZS2FmJNp1coAFzvtCN9BmamE+4aHK8yyUHUSCcJHgXloTyT2A==" crossorigin="anonymous" referrerpolicy="no-referrer" />
<!-- This Page JS -->
<script src="/js/adminJS/findIdForm.js" type="text/javascript"></script>
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
	<main class="container position-absolute top-50 start-50 translate-middle form-signin w-100 m-auto text-center">
		<h1 class="mb-5 fw-bold">아이디 찾기</h1>
		<div class="form-floating">
	    	<input type="text" class="form-control bg-light mt-3" id="name" aria-describedby="idChkResult">
	    	<label for="floatingInput">이름</label>
	    	<small id="idChkResult" class="text-muted">
     			
    		</small>
	    </div>
		<div class="form-floating">
	    	<input type="email" class="form-control bg-light mt-3" id="email" aria-describedby="idChkResult">
	    	<label for="floatingInput">이메일</label>
	    	<small id="idChkResult" class="text-muted">
     			
    		</small>
	    </div>
		<button class="w-100 btn btn-lg btn-primary mb-3 mt-3" type="button" onclick="findId();">아이디 찾기</button>
		<div id="findIdResult"></div>
		<div id="errMsg"></div>
		<button class="w-100 btn btn-lg btn-primary mb-3 mt-3" type="button" onclick="location.href='/'">로그인 페이지</button>
	</main>
</body>
</html>