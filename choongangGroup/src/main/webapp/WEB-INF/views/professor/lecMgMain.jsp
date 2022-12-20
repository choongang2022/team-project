<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%-- <%@ include file="header.jsp"%> --%>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
	<title>Content</title>
	<!-- bottSTrap CSS only -->
	<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.2/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-Zenh87qX5JnK2Jl0vWa8Ck2rdkQ2Bzep5IDxbcnCeuOxjzrPF/et3URy9Bv1WTRi" crossorigin="anonymous"/>
	<!-- bootStrap Icons -->
	<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.9.1/font/bootstrap-icons.css">
	<!-- JavaScript Bundle with Popper -->
	<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.2/dist/js/bootstrap.bundle.min.js" integrity="sha384-OERcA2EqjJCMA+/3y+gxIOqMEjwtxJY7qPCqsdltbNJuaOe923+mo//f6V8Qbsw3" crossorigin="anonymous"></script>
	<!-- jQuery -->
	<script src="http://code.jquery.com/jquery-latest.min.js"></script>
	<!-- font awesome -->
	<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.2.0/css/all.min.css" integrity="sha512-xh6O/CkQoPOWDdYTDqeRdPCVd1SpvCA9XXcUnZS2FmJNp1coAFzvtCN9BmamE+4aHK8yyUHUSCcJHgXloTyT2A==" crossorigin="anonymous" referrerpolicy="no-referrer" />
	<!-- CSS -->
	<link rel="stylesheet" href="/css/stylesLec.css">
	<link rel="stylesheet" href="/css/styles.css">

</head>

<body id="body-pd" style="background-color: rgb(214, 225, 237)">
	<jsp:include page="shortHeadrInfo.jsp"></jsp:include>
	
	<!-- side nav bar -->
	<jsp:include page="sideNavBar.jsp"></jsp:include>
	<!-- /side nav bar -->

	<!------- main content ------------>
	<div class="container-fluid w-100" style=" background-color: rgb(214, 225, 237);">
		<div class="row">

			<!------------- card header  컨텐츠 폼------------->
			<main class="col-9 h-100 w-100">
				<input type="hidden" name="gubun" value="1">
				
				<div class="row m-5">
					<!------------- 컨텐츠 경로 ------------->
					<div class="col-12 rounded-top text-white overflow-auto pt-2 fw-bold" style="background-color: rgb(39, 40, 70); height: 40px;">
						<i class="bi bi-bookmark-fill me-2"></i>학사관리 &gt; 강의관리 </div>
					<!----- card content 내용 ------>
						<div class="col-12 rounded-bottom overflow-auto bg-white p-5" style="min-height: 550px;">
						
						<h2>강의관리</h2><hr>
						<p class="font08">총 <b style="color: red">${lecCnt}</b>개의 수업이 있습니다</p><br>
						<c:forEach var="lec" items="${lecList}">
							<c:if test ="${lec.lecture.status eq '0'}">
								<p style="font-size: 1.3em;">(${lec.lecture.typeCode}${lec.lecture.id}) <b>${lec.lecture.name}</b> _${lec.lecture.grade}학년</p>
								<p class="mb-1 font09 me-3" style="display: inline;">수강인원 : <b>${lec.memberCnt}</b>명 &nbsp;&nbsp;&nbsp; &#183;</p>
								<div class="font09"  style="display: inline;">총 수업시간 : <!-- <b style="color: red">6</b>/ -->${lec.lecture.maxCount}
									<%-- &nbsp; &#183; &nbsp; 휴강 : <b>${statusCnt1}</b> &nbsp; &#183; &nbsp; 보강 : <b>${statusCnt2}</b> --%>
									<div style="display: inline; float: right;">
										<button type="button" class="btn btn-danger btn-sm ms-5 font09 fw-bold"
												onclick="location.href='lecAttendanceCheck?id=${lec.lecture.id}'">&nbsp;&nbsp; 전자출석부  &nbsp; &nbsp;</button>
										<button type="button" class="btn btn-primary btn-sm font09 fw-bold"	
												onclick="location.href='reportList?id=${lec.lecture.id}'">&nbsp;&nbsp; 과제 조회  &nbsp; &nbsp;</button>
										<button type="button" class="btn btn-secondary btn-sm font09 fw-bold"
												onclick="location.href='EvaManagementForm'">강의평가조회</button>
									</div>
								</div>
								<hr class="my-4">	
								<!-- <hr> -->
							</c:if>
						</c:forEach>
					</div>
					
					<!-- footer -->
					<footer class="col-12 mt-5" style="height: 60px; font-size: 12px;">
						<jsp:include page="../footer.jsp"></jsp:include>
					</footer> 
					<!-- </footer>  -->
				</div>
			</main>
		</div> 
	</div> <!-- container div end -->
	<!-- IONICONS -->
	<script src="https://unpkg.com/ionicons@5.2.3/dist/ionicons.js"></script>
	<script src="/js/main.js"></script>
</body>
</html>