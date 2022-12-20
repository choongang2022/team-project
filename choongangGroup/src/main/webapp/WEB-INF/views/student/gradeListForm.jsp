
<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<!DOCTYPE html>
<html>


<!--   ************************************************************************-->
<script src="http://code.jquery.com/jquery-latest.min.js"></script>
<script type="text/javascript">

function getGradeList(vuserId)
{
	//alert("성공")
	/* 내가 셀렉트에서 선택한 인덱스 번째의 값을 가져옴  */
	var value = (selectOp.options[selectOp.selectedIndex].value);
    

	$.ajax({

				
		url : "gradeDetailList",			
		data:{userid : vuserId , ys : value},  /* 아이디와  ys(학기,년도)파라메타 두개 넘겨줌  */				
		dataType : 'json',			
		success:function(data){
			
			//alert("value = "+value);					
			//alert("성공");
					
					
					//학기 년도 별 신청한 과목 성적 조회  테이블생성 
					
					var str = '<tr>';                  //테이블생성 
					$.each(data, (index, obj)=>{
						
			
					str +='<td>' +obj.lec_type +'</td>';
					str +='<td>' +obj.lec_name +'</td>';
					str +='<td>' +obj.lec_id +'</td>';
					str +='<td>' +obj.lec_unit_score +'</td>';
					
					if(obj.sco_attendance > 0){
						
						if(obj.sco_total>=4.5){
							str +='<td>A+</td>';
						}else if(obj.sco_total>=4){
							str +='<td>A</td>';
						}else if(obj.sco_total>=3.5){
							str +='<td>B+</td>';
						}else if(obj.sco_total>=3){
							str +='<td>B</td>';
						}else if(obj.sco_total>=2.5){
							str +='<td>C+</td>';
						}else if(obj.sco_total>=3){
							str +='<td>C</td>';
						}else if(obj.sco_total>=2){
							str +='<td>D+</td>';
						}else{
							str +='<td>F</td>';
						}
					
					}else {
						str +='<td>F</td>';		
						
					}
					
					 str +='</tr>' ;
		               });
		               $("#gradeList").html(str);          //값이 쌓일때마다 계속 넣어줌
		               
		               var str2 = '<tr>';
		               var unitTotal=0;     //토탈신청학점
		               var countUnit = 0;   //토탈 취득학점
		               var countTotal = 0;  // 토탈성적
		               var percentile = 0;   //백분위
		               var avg = 0;      //평균
		               var count = 0;         
		               var ptotal =0;
		               
		               
		               $.each(data, (index, obj)=>{
		            	  unitTotal += obj.lec_unit_score;
		            	   
		            	  if(obj.sco_total>=2) {
		                  countUnit += obj.lec_unit_score;
		            	  }
		                  countTotal += obj.sco_total;
		                  count ++;
		               });
		               
		               
		               avg = countTotal/count;
		           
		               percentile =countTotal*10+54;
		               
		               str2 +='<td>' + unitTotal +'</td>';
		               str2 +='<td>' + countUnit +'</td>';
		               str2 +='<td>' + countTotal +'</td>';
		               str2 +='<td>' + avg.toFixed(1) + '</td>';
		               str2 +='<td>' + percentile + '</td>';
		               str2 +='</tr>' ;
		               $("#scoretotal").html(str2);
		               
		              
		            }
		            
		            
		            
		         });

}



</script>












<!--   ************************************************************************-->






<head>
<meta charset="UTF-8">
<!-- bottSTrap CSS only -->
<link
	href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.2/dist/css/bootstrap.min.css"
	rel="stylesheet"
	integrity="sha384-Zenh87qX5JnK2Jl0vWa8Ck2rdkQ2Bzep5IDxbcnCeuOxjzrPF/et3URy9Bv1WTRi"
	crossorigin="anonymous">
<!-- bootStrap Icons -->
<link rel="stylesheet"
	href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.9.1/font/bootstrap-icons.css">
<!-- JavaScript Bundle with Popper -->
<script
	src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.2/dist/js/bootstrap.bundle.min.js"
	integrity="sha384-OERcA2EqjJCMA+/3y+gxIOqMEjwtxJY7qPCqsdltbNJuaOe923+mo//f6V8Qbsw3"
	crossorigin="anonymous"></script>
<!-- jQuery -->
<script src="http://code.jquery.com/jquery-latest.min.js"></script>
<!-- font awesome -->
<link rel="stylesheet"
	href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.2.0/css/all.min.css"
	integrity="sha512-xh6O/CkQoPOWDdYTDqeRdPCVd1SpvCA9XXcUnZS2FmJNp1coAFzvtCN9BmamE+4aHK8yyUHUSCcJHgXloTyT2A=="
	crossorigin="anonymous" referrerpolicy="no-referrer" />
<!-- CSS -->
<link rel="stylesheet" href="/css/styles.css">

<title>SideBar sub menus</title>
</head>



<body class="" id="body-pd">
	<!-- header -->
	<!-- <nav class="navbar navbar-expand-lg navbar-dark bd-navbar bg-light sticky-top position-fixed fixed-top w-100" style="position : absolute">
        <a class="navbar-brand">
            <button class="btn ms-2" type="button">
                <img class="img-fluid" src="/images/logo2.png" alt="logo2" style="height: 40px;">
            </button>
        </a>
    </nav> -->
	<nav
		class="navbar navbar-expand-lg navbar-dark bd-navbar bg-light sticky-top position-fixed fixed-top w-100"
		style="position: absolute">
		<header
			class="d-flex flex-wrap align-items-center justify-content-center justify-content-md-between">
			<a href="/" class="navbar-brand"> <img class="img-fluid"
				src="/images/logo2.png" alt="logo2" style="height: 40px;"> <use
					xlink:href="#bootstrap"></use> </svg>
			</a>

			<ul
				class="nav col-12 col-md-auto mb-2 justify-content-center mb-md-0">
				<li><a href="#" class="nav-link px-2 link-secondary">Home</a></li>
				<li><a href="#" class="nav-link px-2 link-dark">Features</a></li>
				<li><a href="#" class="nav-link px-2 link-dark">Pricing</a></li>
				<li><a href="#" class="nav-link px-2 link-dark">FAQs</a></li>
				<li><a href="#" class="nav-link px-2 link-dark">About</a></li>
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
                   <!--  <a href="#" class="nav__logo">카테고리</a> -->
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
<!-- main content -->
   <div class="container-fluid w-100" style=" background-color: rgb(214, 225, 237)">
      <div class="row">
      
         <!-- content header -->
         <div class="col-12 px-5 py-4" style=" background-color: rgb(95, 142, 241)">
            <div class="d-flex flex-row mb-2 mt-2">
               <div>
                  <span class="text-white h4">안녕하세요. <span class="fw-bold">${member.name}</span>님!</span>
               </div>
               <div class="border border-1 border-white rounded-pill text-white ms-2"  style="height: 25px;">
                  <div class="font09 align-items-center">&nbsp; 학생  &nbsp;</div>
               </div>
               <div><i class="text-white bi-gear-fill mx-2">  </i></div>
            </div>
            <div class="row">

            <div>
               <span class="text-white font09">${member.major}과&nbsp; &nbsp; ${member.grade}&nbsp;학년 </span>
            </div>
            </div>
            <div class="d-flex flex-low mb-2">
               <div><i class="bi bi-envelope-fill text-white"></i></div>
               <div><span class="text-white ms-2 font09">${member.email}</span></div>
            </div>

         </div>
			<main class="col-9 h-100 w-100">
				<div class="row m-5">
					<!-- card header -->
					<div
						class="col-12 rounded-top text-white overflow-auto pt-2 fw-bold"
						style="background-color: rgb(39, 40, 70); height: 40px;">
						<i class="bi bi-bookmark-fill me-2"></i>학생서비스 <i
							class="bi bi-chevron-right"></i>성적관리 <i
							class="bi bi-chevron-right"></i>성적조회
					</div>
					<!-- card content -->
					<div class="col-12 rounded-bottom overflow-auto bg-light p-3"
						style="min-height: 550px;">


						<!--  ***************************성적조회 ************************************************** -->

<div >
<p class="fw-semibold">



<th>${member.name }</th>
	<th>(${member.userid })</th>
	<th>${member.grade }학년</th>
	<th>${member.stud_status}중</th>




</p> 

</div>

						<div>
						
		<button type="button" class="btn btn-outline-secondary" disabled>총 성적 내역</button>				
						
		
							<table class="table table-striped table-hover"
								style="width: 700px; text-align: center;">
								<thead>
									<tr >
										<th>신청학점</th>
										<th>취득학점</th>
										<th>평점총계</th>
										<th>평균평점</th>
										<th>백분위</th>
										<th>전공</th>
										<th>교양</th>
									<tr>
									<tr>
										<th>${grade.utotal } </th>
										<th>${grade.ptotal } </th>
										<th>${grade.stotal}</th>
										<th>${grade.avg }</th>
										<th>${grade.percentile} </th>
										<th>${grade.majorutotal}</th>
										<th>${grade.subutotal}</th>
									<tr>
								</thead>

							</table>




						</div>




						<!--  학년학기         셀렉트바   -->

						<div>


							<select id="selectOp" class="btn btn-outline-secondary" aria-label="Default select example">
							
								<c:forEach var="y" items="${ysList}">
									<option value="${y.lec_year},${y.lec_semester}">${y.lec_year}년도${y.lec_semester}학기</option>
								</c:forEach>

							</select> 
							<input type="button"  class="btn btn-secondary" value="조회"
								onclick="getGradeList(${member.userid})"> <!--  //아작스 실행  -->

						</div>

                      <!-- 학기 년도별 신청 학점 평점총계 -->

						
						<div>
							<table class="table table-striped table-hover"
								style="width: 700px; text-align: center;">
								<thead>
									<tr>
							
										<th class="text-center">신청학점</th>
										<th class="text-center">취득학점</th>
										<th class="text-center">평점총계</th>
										<th class="text-center">평점평균</th>
										<th class="text-center">백분위</th>
										
										
									<tr>
									
								</thead>
								<tbody id="scoretotal"></tbody>
								
							</table>



						</div>



						<!-- 학기 년도 별 신청한 과목 성적 조회  -->

						<div>
							<table class="table table-striped table-hover"
								style="width: 700px; text-align: center;">
								<thead>
									<tr>
										<th class="text-center">구분</th>
										<th class="text-center">교과명</th>
										<th class="text-center">교과코드</th>
										<th class="text-center">학점</th>
										<th class="text-center">성적</th>
									</tr>
								</thead>
								<tbody id="gradeList"></tbody>

							</table>

						</div>

						<!--  ************************************************************************************ -->




























					</div>
					<!-- footer -->
					<footer class="col-12" style="height: 60px;">
					<jsp:include page="../footer.jsp"></jsp:include>
					
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