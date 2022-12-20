
<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@ include file="header.jsp"%>
<!DOCTYPE html>
<html>


	<!--  ************************************************************************************ -->


<script src="http://code.jquery.com/jquery-latest.min.js"></script>
<script type="text/javascript">


function updateEvaluation(vuserId){
	
	//alert("수정");

	//테이블의 html 태그로 데이터 접근하기.
	var rows = document.getElementById("table").getElementsByTagName("tr");
	console.log(rows.length);	// 줄 개수 6개
	
	var list = []; // 배열들 넣어줄 리스트

	for( var r=0; r<rows.length; r++ ){ //6번 반복

		var arr = []; //배열 생성
		
		var cells = rows[r].getElementsByTagName("th"); // tr 밑의 th 태그 가져옴(첫번째줄)
		var big = cells[0].firstChild.data;				// 첫번째줄의 첫번째칸 :대분류 10
		var small = cells[1].firstChild.data;			// 첫번째줄의 두번째칸 :소분류 20
		//var cell_3 = cells[2].firstChild.data;		// 첫번째줄의 세번째칸 :질문내용 (필요없음)
		var content = cells[3].firstChild.value;		// 첫번째줄의 네번째칸 :수업 내용은 ~~~~ ?
				
		arr .push(big);
		arr.push(small);
		arr.push(content);

		console.log(big);	// 10
		console.log(small);	// 20
		console.log(content);	// 수업 내용은 전반적으로 적절합니까 ? 
				
		list.push(arr);		
	}
	

	
	console.log(list);
	//alert(list);
	//alert(parent);
	
 	$.ajax({
 		url : "realupdateEvaluation",
		data:{
			"rsList" : JSON.stringify(list) //보내려는 데이터를 문자열로 변환하여 넣기
		},
		success:function(data){
			alert("수정 되었습니다.");
			//alert("넘오온데이터 : " + data);
			
			
		},
		
	     error:function(request,status,error){
	    	 console.log(e); // 실패 시 처리
	       }
	});

	
	
	
}



</script>


















	<!--  ************************************************************************************ -->





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

<!--  ************************************************************************************ -->

<style type="text/css">
.big {
	display: none;
} /*값 숨기기  */
</style>




<!--  ************************************************************************************ -->


<title>SideBar sub menus</title>
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
					<div
						class="col-12 rounded-top text-white overflow-auto pt-2 fw-bold"
						style="background-color: rgb(39, 40, 70); height: 40px;">
						<i class="bi bi-bookmark-fill me-2"></i>관리자서비스 <i
							class="bi bi-chevron-right"></i>강의평가 <i
							class="bi bi-chevron-right"></i>강의평가수정 
					</div>
					<!-- card content -->
					<div class="col-12 rounded-bottom overflow-auto bg-light p-3"
						style="min-height: 550px;">



						<!--  ************************************************************************************ -->




  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.2/dist/js/bootstrap.bundle.min.js" integrity="sha384-OERcA2EqjJCMA+/3y+gxIOqMEjwtxJY7qPCqsdltbNJuaOe923+mo//f6V8Qbsw3" crossorigin="anonymous"></script>

		<br>
		<button type="button" class="btn btn-primary" disabled>강의평가 질문 내용 수정</button>
		<hr>
	<input type="hidden" id="cgList3" value="${cgList2}" />
	<div>
		<table class="table table-bordered"  style="width: 1000px; " id="table" >
			<tbody>
				<c:forEach var="cg2" items="${cgList2 }" varStatus="status">
					<tr>
						<th class="big" rowspan="1">${cg2.big_category}</th>
						<th class="big" rowspan="1">${cg2.small_category}</th>
						<th span style="color: 272846;  rowspan="1">질문내용</th>
						<th><input style="width: 900px;  " type="text"
							name="category_content" required="required"
							value="${cg2.category_content }"></th>
					</tr>

				</c:forEach>
			</tbody>

		</table>
	</div>

	<div>
		<%--             <input type="submit" value="수정" onclick="location.href='updateEvaluation?userid=${userid}'"    > --%>
		
			<input class="btn btn-primary"     style="margin-left:900px;" type="submit" value="수정완료" onclick="updateEvaluation(${userid})" />
		
		<!--  //아작스 실행  -->

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