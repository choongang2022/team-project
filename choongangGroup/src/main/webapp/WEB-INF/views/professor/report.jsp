<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%-- <%@ include file="header.jsp"%> --%>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
   <title>과제관리</title>
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
   <!-- This Page JS -->
   <script src="/js/dhJS/report.js" type="text/javascript"></script>
</head>

<body id="body-pd">

	<!-- shortHeadrInfo -->
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
                  <i class="bi bi-bookmark-fill me-2"></i>학사관리 &gt; 강의관리 &gt; 과제관리</div>
               <!----- card content 내용 ------>
                  <div class="col-12 rounded-bottom overflow-auto bg-light p-5" style="min-height: 960px;">
                  
                  	<h2>과제관리</h2><hr>
					<div class="container-fluid p-4">
						<!-- 강의 목록 select box -->
						<select class="form-select w-25 mt-3" id="selLec" aria-label="Default select example" onchange="showReport(0)">
							<c:forEach var="lecture" items="${lectureList }">
								<option value="${lecture.id }">(${lecture.typeCode}${lecture.id}) <b>${lecture.name}</b> _${lecture.grade}학년</option>
							</c:forEach>
						</select>
						<!-- Buttons -->
						<div class="d-flex justify-content-end mb-2">
							<!-- 과제 성적 입력 button -->
							<div class="btn btn-danger mx-1" style="font-size: small; width: 104px;" onclick="submitScore()">점수등록</div>
						</div>
						<div class="d-flex justify-content-end">
							<!-- 해당 강의를 듣는 학생 count (ajax) -->
							<div class="me-auto">total : <span id="totalCount" class="text-danger">999</span></div>
							<div class="btn btn-primary mx-1" style="font-size: small;" onclick="downloadFileAll()">전체내려받기</div>
							<div class="btn btn-secondary mx-1" style="font-size: small;" onclick="downloadFileSel()">선택내려받기</div>
						</div>
						<!-- table -->
						<table class="table table-striped mt-2">
							<thead>
								<tr>
									<th>No</th>
									<th>선택</th>
									<th>학번</th>
									<th>제출자</th>
									<th>제출여부</th>
									<th>파일명</th>
									<th>제출일</th>
									<th>점수</th>
									<th>평가</th>
								</tr>
							</thead>
							<!-- 과제 목록 출력 부분 (ajax) -->
							<tbody id="ajaxAppend">
							</tbody>
						</table>
						<!-- 페이지 네비게이션 출력 부분 (ajax) -->
						<div class="d-flex justify-content-center " id="ajaxPagination">
						</div>
					</div>
				</div>
				<!-- Spring Security CSRF TOKEN(csrf옵션 disabled이므로 사용되지 않는 값들이다.) -->
				<div>
					<input type="hidden" id="page" name="page" value="0">
					<input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}" />
				</div>
				<div>
					
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