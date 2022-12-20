<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %> 
<!DOCTYPE html>
<html>
<head>

<script type="text/javascript">
function submit(obj){
	obj.submit();	
	}
</script>

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

    <title>SideBar sub menus</title>
</head>

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
                        <i class="bi bi-bookmark-fill me-2"></i>학생서비스 <i class="bi bi-chevron-right"></i>학사관리 <i class="bi bi-chevron-right"></i>강의 목록 조회
                    </div>
                    <!-- card content -->  
                    <div class="col-12 rounded-bottom overflow-auto bg-light p-3" style="min-height: 550px;"> 
                        <!-------------- 본문 ------------->
                        
                        <!-- 장바구니 메인 제목-->
                        <div class="mt-3 mb-3">                    
                       	  <span class="fs-2 fw-bold">신청 강의목록 </span>                         
                        </div> 
                        <!-- class="fw-bold border rounded-top " style="background-color:#EAEAEA; height: 45px;" -->
                       	<div class="fw-bold">
                       		<span style="line-height: 45px;">${year }학년도 ${semester }학기 신청강의</span>
                       		
                    		<!-- 강의명으로 검색 -->
                       		<form action="lectureList" method="get" class="row row-cols-lg-auto g-3 float-end" >
	                       		  
								 
								 <!-- 년도,학기 select -->
								 <div class="col-12">	
		                       		<input type="hidden" name="userid" value="${userid }">
		                       		
									<select class="form-select" name="year" required="required">										
										<option label="년도"/>
										<c:forEach var="list" items="${yearList }">
											<option value="${list}" >${list}년</option >														
										</c:forEach>		
									</select>
								 </div>	
								  <div class="col-12">	
									<select class="form-select" name="semester" required="required">										
										<option label="학기"/>
										<option value="1" >1학기</option >	
										<option value="2" >2학기</option >																									
									</select>	
									
									
								</div>
								<div class="col-12">
									<input class="btn btn-primary" type="submit" value="검색">	
								</div>
							</form>
							
							
								<!----------- 강의 리스트 -------------->
							<table class="table table-striped mt-5">
								<thead>
									<tr>
										<th>강의코드</th><th>강의명</th><th>학년</th><th>강의시간</th><th>교수명</th>
										<th>이수구분</th><th>전공</th><th>학점</th><th>강의계획서</th><th>과제</th>
									</tr>
								</thead>
							
								
								<!-- 수강 전체 과목 -->
								
								<c:forEach var="lec" items="${list}">
									<tr>
										<td>${lec.lecture.id }</td><td>${lec.lecture.name }</td><td>${lec.lecture.grade }</td>
										<td>${lec.lecture.day1}${lec.lecture.time1}, ${lec.lecture.day2}${lec.lecture.time2}</td><td>${lec.lecture.prof }</td><td>${lec.lecture.type }</td>
										<td>${lec.lecture.major }</td><td>${lec.lecture.unitScore }</td><td><i class="bi-file-earmark-pdf-fill" style="color: red"> </i>${lec.lecture.fileName }</td>
										<td><i class="bi-cloud-arrow-up-fill" style="color: rgb(95, 142, 241);"></i> <a href = "fileInsertForm?lecId=${lec.lecture.id }&userid=${userid}">제출하기</a></td>
										
									</tr>	
								</c:forEach>
								
								
							</table>	
							
							
							
							
                       	</div>
                       		
                       		
                       <!-- 본문끝  -->	
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