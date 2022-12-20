<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%-- <%@ include file="header.jsp"%> --%>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
   <title>계정관리</title>
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
   <script src="/js/adminJS/adminMain.js" type="text/javascript"></script>
</head>
<script>
	
</script>
<style>
    #body-pd {
        padding: 0;
        margin-top: 3.75em;
    }
</style>
<body id="body-pd">
	<!-- shortHeadrInfo -->
	<jsp:include page="mainLogo.jsp"></jsp:include>
   <!------- main content ------------>
   <div class="container-fluid w-100" style=" background-color: rgb(214, 225, 237);">
      <div class="row">

         <!------------- card header  컨텐츠 폼------------->
         <main class="col-9 h-100 w-100">
            
            <div class="row m-5">
                <!------------- 컨텐츠 경로 ------------->
                <div class="col-12 rounded-top text-white overflow-auto pt-2 fw-bold" style="background-color: rgb(39, 40, 70); height: 40px;">
                    <i class="bi bi-bookmark-fill me-2"></i>
                    회원 계정 관리
                </div>
                <!----- card content 내용 ------>
                <div class="col-12 rounded-bottom overflow-auto bg-light p-5" style="min-height: 960px;">
                    <h2>계정관리</h2><hr>
                    <div class="container-fluid">
                        <div class="row">
                            <div class="col-12 mt-2">
								<!-- 해당 강의를 듣는 학생 count (ajax) -->
                                <button class="btn btn-primary" onclick="location.href='/admin/createMemberForm'">계정생성</button>
                                <!-- <button class="btn btn-primary" onclick="deleteMember()">선택계정삭제</button> -->
                            </div>
                            <div class="col-12 mt-4">
								<div class="me-auto">total : <span id="totalCount" class="text-danger">999</span></div>
                                <table class="table table-striped">
                                    <thead>
                                        <tr class="table-secondary">
											<!-- <th>선택</th> -->
                                            <th>사용자코드</th>
                                            <th>이름</th>
                                            <th>부서</th>
                                            <th>휴대폰</th>
                                            <th>이메일</th>
                                        </tr>
                                    </thead>
                                    <tbody id="ajaxAppend">
                                    </tbody>
                                </table>
                                <!-- 페이지 네비게이션 출력 부분 (ajax) -->
                                <div class="d-flex justify-content-center " id="ajaxPagination">
                                </div>
								<input type="hidden" id="currentPage" name="currentPage" value="">
                            </div>
                        </div>
                    </div>
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