<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ include file="header.jsp"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<!-- bottSTrap CSS only -->
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.2/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-Zenh87qX5JnK2Jl0vWa8Ck2rdkQ2Bzep5IDxbcnCeuOxjzrPF/et3URy9Bv1WTRi" crossorigin="anonymous">		
<!-- bootStrap Icons -->
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.9.1/font/bootstrap-icons.css">
<!-- JavaScript Bundle with Popper -->
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.2/dist/js/bootstrap.bundle.min.js" integrity="sha384-OERcA2EqjJCMA+/3y+gxIOqMEjwtxJY7qPCqsdltbNJuaOe923+mo//f6V8Qbsw3" crossorigin="anonymous"></script>
<!-- jQuery -->
<script src="http://code.jquery.com/jquery-latest.min.js"></script>
<!-- font awesome -->
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.2.0/css/all.min.css" integrity="sha512-xh6O/CkQoPOWDdYTDqeRdPCVd1SpvCA9XXcUnZS2FmJNp1coAFzvtCN9BmamE+4aHK8yyUHUSCcJHgXloTyT2A==" crossorigin="anonymous" referrerpolicy="no-referrer" />
<!-- CSS -->
<link rel="stylesheet" href="/css/styles.css">
<title>학생관리홈</title>
<script type="text/javascript">
	function studSearch() {
		var grade = document.getElementById("searchGrade").value;
		var major = document.getElementById("searchMajor").value;
		var studStatus = document.getElementById("searchStatus").value;
		var name = document.getElementById("searchName").value;
		console.log("검색하기");

	    $.ajax({
			url 	: "studSearch",
			data	: {"grade"	    : grade,
					   "major"      : major,
					   "studStatus" : studStatus,
					   "name"	    : name
						},
			dataType: 'text',
			type:'post',
			success	: function(data){
				console.log(data);
				console.log(JSON.parse(data));
				var html = "";
				if(data.length > 0){
					$('#studTable > tbody').empty();
					
					$.each(JSON.parse(data), function(index, item){
						html += "<tbody><tr onclick='studDetail("+item.userid+")'>";
						html += "<td class='text-center'>" + (index+1) + "</td>";
					 	html += "<th class='text-center'>" + item.userid + "</th>"; 
						html += "<td class='text-center'>" + item.name +"</td>";
						html += "<td class='text-center'>" + item.grade + "</td>";
						html += "<td class='text-center'>" + item.major+ "</td>";
						html += "<td class='text-center'>" + item.admission+ "</td>";
						html += "<td class='text-center'>" + item.studStatus+ "</td>";
						html += "</tr>"; 
						html += "</tbody>";
					});
					
					console.log(html);
					 $('#studTable > thead').after(html); 
				}
			}
		});
	}
	
	function studDetail(id) {
		console.log("학생 클릭 ===> " + id);
		$.ajax({
			url 	: "studDetail",
			data	: {userid : id},
			dataType: 'text',
			success	: function(data){
				console.log("성공===> " + data );
				var stud = JSON.parse(data);
				console.log("==>" + stud.name);
				document.getElementById("name").value=stud.name;
				document.getElementById("userid").value=stud.userid;
				document.getElementById("admType").value=stud.admType;
				document.getElementById("admission").value=stud.admission;
				document.getElementById("gender").value=stud.gender;
				document.getElementById("major").value=stud.major;
				document.getElementById("nation").value=stud.nation;
				document.getElementById("phone").value=stud.phone;
				document.getElementById("subphone").value=stud.subphone;
				document.getElementById("studStatus").value=stud.studStatus;
				document.getElementById("address").value=stud.address;
				document.getElementById("birth").value=stud.birth;
			}
		});
	}
	
	
	function studUpdate(studFrm) {
		 if (confirm("학생 정보를 수정하시겠습니까?") == true) {
			 alert("수정되었습니다.");
			 studFrm.action = "studUpdate";
			 studFrm.submit();
			 return true;
		 }
		 else {
			 alert("취소되었습니다.")
			 return false;
		 }
	}
</script>
<style type="text/css">
	#btnNewAppr {
		background-color: #0c5df4;
		border : 0;
	}
	
	.btnProcess {
		font-size: 12px;
		color: #7F7F7F;
	}
</style>
</head>

<body class="" id="body-pd" onload="printClock()">
    <!-- header -->
    <!-- <nav class="navbar navbar-expand-lg navbar-dark bd-navbar bg-light sticky-top position-fixed fixed-top w-100" style="position : absolute">
        <a class="navbar-brand">
            <button class="btn ms-2" type="button">
                <img class="img-fluid" src="/images/logo2.png" alt="logo2" style="height: 40px;">
            </button>
        </a>
    </nav> -->
    <nav class="navbar navbar-expand-lg navbar-dark bd-navbar bg-light sticky-top position-fixed fixed-top w-100" style="position : absolute">
        <header class="d-flex flex-wrap align-items-center justify-content-center justify-content-md-between">
          <a href="/" class="navbar-brand">
            <img class="img-fluid" src="/images/logo2.png" alt="logo2" style="height: 40px;"><use xlink:href="#bootstrap"></use></svg>
          </a>
    
          <ul class="nav col-12 col-md-auto mb-2 justify-content-center mb-md-0">
  			<jsp:include page="navHeader.jsp"></jsp:include>
          </ul>
        </header>
    </nav>
    <!-- /header -->
    <!-- side nav bar -->
    <div class="l-navbar" id="navbar">
		<nav class="navv">
			<div>
				<div class="nav__brand">
					<ion-icon name="menu-outline" class="nav__toggle" id="nav-toggle"></ion-icon>
					<a href="/manager/approval" class="nav__logo">학사관리</a>
				</div>
				<div class="nav__list">
					<div href="" class="nav__link collapses">
						<!-- <ion-icon name="folder-outline" class="nav__icon"></ion-icon> -->
						<!-- <i class="bi bi-gear-fill nav__icon" name="folder-outline"></i> -->
						<i class="bi bi-mortarboard-fill nav__icon" name="folder-outline"></i>
						<span class="nav_name">학사관리</span>

						<ion-icon name="chevron-down-outline" class="collapse__link"></ion-icon>

						<ul class="collapse__menu" style="width: 200px;">
							<a href="/manager/studentManage" class="collapse__sublink">학생관리</a></br>
							<a href="/manager/professorManage" class="collapse__sublink">교수관리</a></br>
							<a href="/manager/EvaManagementForm" class="collapse__sublink">강의 평가 관리</a></br>
							<a href="/manager/updateFormEvaluation" class="collapse__sublink">강의 평가 수정</a></br>
						</ul>
					</div>
				</div>
				<a href="/logout" class="nav__link"> <ion-icon
						name="log-out-outline" class="nav__icon"></ion-icon> <span
					class="nav_name">로그아웃</span>
				</a>
			</div>
		</nav>
	</div>
    <!-- /side nav bar -->
    <!------- main content ------------>
	<div class="container-fluid w-100 row" style=" background-color: rgb(214, 225, 237);">
	<!-- <div class="row"> -->

		<!-- content header -->
		<jsp:include page="contentHeader.jsp"></jsp:include>
                    <!-- card header -->
                    <div class="col-12 rounded-top text-white overflow-auto pt-2 fw-bold" style="background-color: rgb(39, 40, 70); height: 40px;"> 
                        <i class="bi bi-bookmark-fill me-2"></i>학사관리 <i class="bi bi-chevron-right"></i>학생관리 
                    </div>
                    <!-- card content -->  
                    <div class="col-12 rounded-bottom overflow-auto bg-light p-3" style="min-height: 550px;"> 
                        <div id="titleInBox" style="font-weight: bold; font-size: 19px;">학생관리홈 <span onclick=" location.href = 'studentManage';" class="badge text-bg-secondary">전체조회</span>
						</div>
						<div id="containerBox">
							<div style="border-top: 1px dashed #c9c9c9; margin: 10px 0;"></div>
							<form action="">
								<div class="mt-3">
								<select class="form-select-sm" name="grade" id="searchGrade" style="width: 8%;">
									<option value="" selected>선택</option>
									<option value="1">1학년</option>
									<option value="2">2학년</option>
									<option value="3">3학년</option>
									<option value="4">4학년</option>
								</select><span class="font09 ms-1" style=" margin-right: 20px;">학년</span>
								<select class="ms-2 form-select-sm" style="width: 12%;" name="major" id="searchMajor">
									<option value="" selected>선택</option>
									<option value="컴퓨터공학과">컴퓨터공학과</option>
									<option value="소프트웨어과">소프트웨어과</option>
								</select><span class="font09 ms-1" style=" margin-right: 20px;">전공</span>
								
								<span class="font09 ms-1">학적상태:</span>
								<select class="ms-2 form-select-sm" style="width: 8%;" name="studStatus" id="searchStatus">
									<option value="" selected>선택</option>
									<option value="재학">재학</option>
									<option value="휴학">휴학</option>
									<option value="졸업">졸업</option>
									<option value="퇴학">퇴학</option>
								</select>
								
								
								<div class="input-group px-0 " style="width: 40%; float: right; margin-right: 200px;">
									<label class="form-label me-2 mb-0 align-self-center font09">학생명:</label>
									<input class="form-control form-sm rounded-1" type="text" name="name"
											aria-describedby="button-search" style="height: 31px;" id="searchName">
			
									<button class="btn btn-secondary btn-sm" id="button-search" type="button" onclick="studSearch()">검색</button>
								</div>
								</div>
							</form>
							
							<div class="btnProcess" style="clear:both; text-align: right;">총 학생 수는 ${stuTotal}명 입니다.</div>
							<div class="scroll_wrap" style="height: 200px; overflow: scroll;">
							<table class="table table-hover" style="font-size: 14px; text-align: center; margin-top: 10px;" id="studTable">
								<thead class="table-secondary">
									<tr>
										<th>순번</th>
										<th>학번</th>
										<th>이름</th>
										<th>학년</th>
										<th style="width: 57%;">전공</th>
										<th>입학일</th>
										<th>학적상태</th>
									</tr>
								</thead>
								<tbody>
									<tbody>
									<c:forEach var="student" items="${studentList}">
									<c:set var="i" value="${i+1}"></c:set>
								    <tr onclick="studDetail(${student.userid})">
								      <td>${i}</td>
								      <th scope="row">${student.userid }</th>
								      <td>${student.name }</td>
								      <td>${student.grade }</td>
								      <td>${student.major }</td>
								      <td>${student.admission }</td>
								      <td>${student.studStatus }</td>
								    </tr>
								    </c:forEach>
								</tbody>
							</table>
							</div>
							
							<div id="titleInBox" style="font-weight: bold; font-size: 19px; margin-top: 30px;">학생 상세정보</div>
							<div style="border-top: 1px dashed #c9c9c9; margin: 10px 0;"></div>
							
							<form name="studFrm" id="studFrm" action="" method="post">
								<table class="table font09 text-center">
									<tr>
										<th class="table-secondary text-center " scope="col" style="width: 9%; vertical-align:middle;">이름</th>
										<td class="p-2" style="width:16%;">
											<input class="form-control text-center mx-0 form-inline form-control-sm " type="text" id="name" name="name" readonly="readonly">
										</td>
										<th class="table-secondary text-center " scope="col" style="width: 9%; vertical-align:middle;">학번</th>
										<td class="p-2" style="width:16%;">
											<input class="form-control text-center mx-0 form-inline form-control-sm " type="text" id="userid" name="userid" readonly="readonly">
										</td>
										<th class="table-secondary me-0" scope="col" style="vertical-align:middle; width: 9%;">입학유형</th>
										<td>
											<input class="form-control text-center mx-0 form-inline form-control-sm " type="text" id="admType" name="admType" readonly="readonly">
										</td>
										<th class="table-secondary" scope="col" style="width: 9%; vertical-align:middle;">입학일</th>
										<td>
											<input class="form-control text-center mx-0 form-inline form-control-sm " type="text" id="admission" name="admission" readonly="readonly">
										</td>
									</tr>
									
									<tr>
										<th class="table-secondary" scope="col" style="width: 9%; vertical-align:middle;">성별</th>
										<td>
											<select id="gender" name="gender" class="form-select form-select-sm me-0 " style="margin: 0;" required="required">
											<option value="" selected>선택</option>
											<option value="남">남자</option>
											<option value="여">여자</option>
										</select>
										</td>
										<th class="table-secondary text-center" scope="col" style="width: 9%; vertical-align:middle;">전공</th>
										<td class="p-2">
											<select id="major" name="major" class="form-select form-select-sm me-0 " style="margin-left: 0;" required="required">
												<option value="" selected>선택</option>
												<option value="컴퓨터공학과">컴퓨터공학과</option>
												<option value="소프트웨어과">소프트웨어과</option>
											</select>
										</td>
										
										<th class="table-secondary" scope="col" style="width: 9%; vertical-align:middle;">연락처</th>
										<td  style="width:16%;">
											<input class="form-control text-center mx-0 form-inline form-control-sm " type="text" id="phone" name="phone" readonly="readonly">
										</td>
										<th class="table-secondary" scope="col" style="width: 9%; vertical-align:middle;">비상연락처</th>
										<td>
											<input id="subphone" name="subphone" class="form-control text-center mx-0 form-inline form-control-sm" type="text" readonly="readonly">
										</td>
									</tr>
					
									
									<tr>
										<th class="table-secondary text-center" scope="col" style="width: 9%; vertical-align:middle;">학적상태</th>
										<td class="p-2">
											<select id="studStatus" name="studStatus" class="form-select form-select-sm me-0 " style="margin-left: 0;" required="required">
												<option value="" selected>선택</option>
												<option value="재학">재학</option>
												<option value="휴학">휴학</option>
												<option value="졸업">졸업</option>
												<option value="퇴학">퇴학</option>
												<option value="자퇴">자퇴</option>
											</select>
										</td>
										<th class="table-secondary me-0" scope="col" style="vertical-align:middle; width: 9%;">국적</th>
										<td>
											<select id="nation" name="nation" class="form-select form-select-sm " style="margin: 0;" required="required">
												<option value="대한민국" selected>대한민국</option>
												<option value="일본">일본</option>
												<option value="중국">중국</option>
										</select>
										</td>
										<th class="table-secondary me-0" scope="col" style="vertical-align:middle; width: 9%;">주소</th>
										<td>
											<input id="address" name="address" class="form-control form-control-sm text-start" type="text" readonly="readonly">
										</td>
										<th class="table-secondary me-0" scope="col" style="vertical-align:middle; width: 9%;">생년월일</th>
										<td>
											<input id="birth" name="birth" class="form-control form-control-sm text-start" type="text" readonly="readonly">
										</td>
									</tr>
									</table>
								<div class="d-flex justify-content-center">
									<button type="button" id="btnUpdate" onclick="studUpdate(studFrm)" class="btn btn-primary btn-sm" style="font-weight: bold; margin-right: 10px;">수정</button>
									<!-- <button type="button" onclick="studDelete()" class="btn btn-secondary btn-sm" style="font-weight: bold;">삭제</button> -->
								</div>
								</form>
							</div>
						</div>
                    </div>
                   </main>
                   <jsp:include page="../footer.jsp"></jsp:include>
	        </div>
	    </div>
	    
    <!-- IONICONS -->
    <script src="https://unpkg.com/ionicons@5.2.3/dist/ionicons.js"></script>
    <!-- JS -->
    <script src="/js/main.js"></script>
</body>
</html>