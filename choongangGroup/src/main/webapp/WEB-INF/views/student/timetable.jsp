<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %> 
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
<link rel="stylesheet" href="/css/timetable.css">
<link rel="stylesheet" href="/css/styles.css">


    <title>SideBar sub menus</title>
</head>

<script type="text/javascript" src="js/jquery.js"></script>
<script type="text/javascript">


	function submit(lecId, userid){
		$.ajax({
			url:"/student/like",
			data:{lecId : lecId , userid : userid},
			dataType:'text',
			success:function(data){
				const result = $.trim(data);

				if(result == 1){
				alert("성공")
				location.reload();
				}else if(result == 0){
					alert("중복된 강의입니다.")
				}else if(result == 2){
					alert("시간이 중복되었습니다.")
				}else{
					alert("최대학점을 초과했습니다 [신청가능 최대학점 : 21학점]")
				}
			}		
		});	
	}
	
	$(document).ready(function(){
	var color = '#';
	var letters = ['f6c9cc', 'a8c0c0', 'FEBF36', 'FF7238', '6475A0', 'acc7bf', '5e5f67', 'c37070', 'eae160', 'bf7aa3', 'd7d967'];
	color += letters[Math.floor(Math.random() * letters.length)]; 
	document.getElementById('wrap').style.background = color; 
	document.getElementById('wrap2').style.background = color; 
	});
	

    </script>



<body class="" id="body-pd">
  
    <nav class="navbar navbar-expand-lg navbar-dark bd-navbar bg-light sticky-top position-fixed fixed-top w-100" style="position : absolute">
        <header class="d-flex flex-wrap align-items-center justify-content-center justify-content-md-between">
          <a href="/" class="navbar-brand">
            <img class="img-fluid" src="/images/logo2.png" alt="logo2" style="height: 40px;"><use xlink:href="#bootstrap"></use></svg>
          </a>
    
  
        </header>
    </nav>
    <!-- /header -->
   	<!----------------------- side nav bar ---------------------------------->
    <div class="l-navbar" id="navbar">
        <nav class="navv">
            <div>
                <div class="nav__brand">
                    <ion-icon name="menu-outline" class="nav__toggle" id="nav-toggle"></ion-icon>
                 
                </div>
                <div class="nav__list">
                	<div href="#" class="nav__link collapses">
                        <i class="bi bi-person-rolodex"></i>
                        <span class="nav_name">학사관리</span>

                        <ion-icon name="chevron-down-outline" class="collapse__link"></ion-icon>

                        <ul class="collapse__menu" style="width: 200px;">
                            <li><a href="/student/listEmp" class="collapse__sublink">학적정보 조회</a></li>
                            <li><a href="/student/lectureListForm" class="collapse__sublink">강의목록 조회</a></li>
                            
                            <li><a href="/student/timetable" class="collapse__sublink">시간표 조회</a></li>
                           

                        </ul>
                    </div>
                    

					<a href="/student/gradeList" class="nav__link">
	                    <i class="bi-mortarboard"></i>
	                    <span class="nav_name">&nbsp;성적 관리</span>
	                </a>
		

					<a href="/student/evaluationList" class="nav__link">
	                    <i class="bi-pencil"></i>
	                    <span class="nav_name">&nbsp;강의 평가</span>
	                </a>


					<a href="/student/applyIndex" class="nav__link">
	                    <i class="bi bi-box-arrow-up-right"></i>
	                    <span class="nav_name">&nbsp;수강 신청</span>
	                </a>
                    <div href="/student/shopList" class="nav__link collapses">
                        <i class="bi bi-book"></i>
                        <span class="nav_name">&nbsp;교재 구매</span>

                        <ion-icon name="chevron-down-outline" class="collapse__link"></ion-icon>

                        <ul class="collapse__menu" style="width: 200px;">
                            <li><a href="/student/shopList" class="collapse__sublink">교재 목록</a></li>
                            <li><a href="/student/cartList" class="collapse__sublink">장바구니</a></li>
                            <li><a href="/student/orderList" class="collapse__sublink">주문 목록</a></li>
                        </ul>
                    </div>
                </div>
                <a href="/logout" class="nav__link">
                    <i class="bi-power"></i>
                    <span class="nav_name">&nbsp; Log out</span>
                </a>
            </div>
        </nav>
    </div>
    <!-- /side nav bar -->
<jsp:include page="header.jsp"></jsp:include>
	<!-- main content -->
	<div class="row">
		
	
    <div class="container-fluid w-100" style=" background-color: rgb(214, 225, 237)">
		
            <main class="col-9 h-100 w-100">
                <div class="row m-5">
                    <!-- card header -->
                    <div class="col-12 rounded-top text-white overflow-auto pt-2 fw-bold" style="background-color: rgb(39, 40, 70); height: 40px;"> 
                        <i class="bi bi-bookmark-fill me-2"></i>학생서비스 <i class="bi bi-chevron-right"></i>강의목록 조회 <i class="bi bi-chevron-right"></i>과제 제출
                    </div>
                    
                    <!------------------- 장바구니 신청 ------------------------------>  
                    <div class="col-12 rounded-bottom overflow-auto bg-light p-3" style="min-height: 550px;"> 
                    	<div class="d-flex flex-row">                    		
                    	 	<div class="col-6 mx-2 ">
                    	 	<!-----------------장바구니 전체 ------------------------>
		                    <!--메인 제목-->
	                        <div class="mt-3 mb-3">                    
	                       	  <span class="fs-2 fw-bold">과제 파일 업로드 </span>                         
	                        </div> 
	                       	
							<div class="col-md-6  rounded overflow-auto bg-light p-4" style="max-height: 300px;"> 
							<h5>시간표</h5><hr>
							<!--------------------------------- 시간표 -------------------------------------->
							<div class="mt-1 timetable" >
								<table class="timetable" style="background-color: #F2F8F8 ; color: 	#003A9D" >								
												<thead >
												<tr >
													<th style="width: 6%; ">시간</th><th>월</th><th>화</th><th>수</th><th>목</th><th>금</th>											
												</tr>
												</thead>									
												<tbody>			
													
									<c:forEach var="j" begin="1" end="7">	
										<tr>
											<td style="width: 6%">${j }교시</td>	
											
											<c:forEach var="d" items="${day }">
															
												<c:forEach var="lec" items="${list }" >	
													<c:if test="${lec.lecture.day1 eq d and lec.lecture.time1 le j and lec.lecture.time1+lec.lecture.hour1 gt j}">
														<c:set var="day1" value="${lec.lecture.day1 }"></c:set> 
														<c:set var="name1" value="${lec.lecture.name }"></c:set>
														<c:set var="time1" value="${lec.lecture.time1 }"></c:set>
														<c:set var="hour1" value="${lec.lecture.hour1 }"></c:set>
													</c:if>	
													
													
													
													<c:if test="${lec.lecture.day2 eq d and lec.lecture.time2 le j and lec.lecture.time2+lec.lecture.hour2 gt j}">
														<c:set var="day2" value="${lec.lecture.day2 }"></c:set> 
														<c:set var="name2" value="${lec.lecture.name }"></c:set>
														<c:set var="time2" value="${lec.lecture.time2 }"></c:set>
														<c:set var="hour2" value="${lec.lecture.hour2 }"></c:set>
													</c:if>															
												</c:forEach>
												
												<c:choose>
													<c:when test="${day1 eq d and time1+hour1 gt j}"> 
													 	<td style="background-color: #6799FF; color: white;">${name1 }</td>
													</c:when>
													<c:when test="${day2 eq d and time2+hour2 gt j}"> 
													 	<td style="background-color: #B2CCFF; color: white">${name2 }</td>
													</c:when>
													<c:otherwise>
														<td></td>
													</c:otherwise>
												</c:choose>
											</c:forEach>	
											</tr>
										</c:forEach>	
													 
									</tbody>																	
								</table> 
								
								
							</div>	
								
								
								

																				
							</div>
						</div>
                    </div>
                    <!-- footer -->
                    <footer class="col-12" style="height: 60px;">
                        footer
                    </footer>    
                </div>
            </main>
        </div>
    </div>
    <!-- IONICONS -->
    <script src="https://unpkg.com/ionicons@5.2.3/dist/ionicons.js"></script>
    <!-- JS -->
    <script src="/js/main.js"></script>
</body>
</html>