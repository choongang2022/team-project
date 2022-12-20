<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%-- <%@ include file="header.jsp"%> --%>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
   <title>강의계획서</title>
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
   <!-- pdfJs -->
   <script src="/js/pdfjs/build/pdf.js" type="text/javascript"></script>
   <!-- pdfObjectJs -->
   <script src="/js/pdfjs/build/pdfobject.js" type="text/javascript"></script>
   <!-- This Page JS -->
   <script src="/js/dhJS/lecPlan.js" type="text/javascript"></script>
</head>

<style>
    .pdfobject-container { height: 800px; border: 1rem solid rgba(0,0,0,.1); }
</style>

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
                  <i class="bi bi-bookmark-fill me-2"></i>학사관리 &gt; 강의정보 &gt; 강의계획서 </div>
               <!----- card content 내용 ------>
                  <div class="col-12 rounded-bottom overflow-auto bg-light p-5" style="min-height: 550px;">
                  
                    <h2>강의계획서</h2><hr>
                    <div class="container-fluid p-5">
                        <div class="d-flex flex-row">
                            <div class="fw-bold">
                                강의조회
                            </div>
                            <div class="d-flex flex-row ms-3">
                                <div class="align-middle">
                                    학년도
                                </div>
                                <div class="px-1">
                                    <select name="year" id="selYear">
                                        <option value="2023">2023</option>
                                        <option value="2022">2022</option>
                                        <option value="2021">2021</option>
                                    </select>
                                </div>
                            </div>
                            <div class="d-flex flex-row">
                                <div class="align-middle">
                                    학기
                                </div>
                                <div class="px-1">
                                    <select name="year" id="selSeme">
                                        <option value="1">1</option>
                                        <option value="2">2</option>
                                    </select>
                                </div>    
                            </div>
                            <div class="d-flex flex-row px-1">
                                <div>
                                    <button class="btn btn-secondary py-1" onclick="showLecList()" style="font-size: small; height: 27px; width: 60px;">검색</button>
                                </div>
                            </div>
                        </div>
                        <div class="row mt-3">
                            <div class="col-12" style="padding-right: 23px;">
                                <table class="table table-bordered mb-0">
                                    <thead class="table-secondary">
                                        <tr class="align-middle text-center">
                                            <th style="width: 4%;">번호</th>
                                            <th style="width: 15%;">개설학과</th>
                                            <th style="width: 9%;">강의코드</th>
                                            <th style="width: 15%;">강의명</th>
                                            <th style="width: 9%;">이수구분</th>
                                            <th style="width: 5%;">학점</th>
                                            <th style="width: 5%;">시수</th>
                                            <th style="width: 7%;">강의계획서 파일</th>
                                            <th style="width: 20%;">강의계획서 업로드</th>
                                        </tr>
                                    </thead>
                                </table>
                            </div>
                           
                            <div class="col-12" style="height: 200px; padding-right: 1px; overflow-y: scroll;">
                                <table class="table table-bordered table-hover align-middle mt-0" id="ajaxAppend">
                                </table>
                            </div>
                        </div>
                        <div class="row mt-5">
                            <div class="col-12 d-flex">
                                <div class="fw-bold">
                                    강의계획서 작성
                                </div>
                                <div class="d-flex flex-row ms-3">
                                   <input type="text" id="selectedLec" class="form-control form-control-sm bg-light ms-1" value="선택된 강의 없음" readonly style="height: 30px; width: 256px;">
                                </div>
                                
                                <div class="ms-auto">
                                    <button class="btn btn-secondary" style="font-size: small;" onclick="editorMode()">편집모드</button>
                                    <button class="btn btn-primary" style="font-size: small;" onclick="insertOrUpdatePlan()">작성완료</button>
                                    <button class="btn btn-dark" style="font-size: small;" onclick="generatePdf()">PDF다운로드</button>
                                    <button class="btn btn-danger" style="font-size: small;" onclick="deletePlan()">강의계획서삭제</button>
                                </div>
                            </div>
                            <div class="col-12">
                                <div class="row">
                                    <div class="col-3 fw-bold">교수정보</div>
                                    <div class="col-12 mt-2">
                                        <table class="table table-bordered">
                                            <thead>
                                                <tr class="align-middle text-center">
                                                    <th class="table-secondary" style="width: 70px;">교수명</th>
                                                    <td style="width: 250px;">
                                                        <input class="form-control" type="text" id="profName" name="profName" value="${member.name}" readonly>
                                                    </td>
                                                    <th class="table-secondary" style="width: 70px;">학과</th>
                                                    <td>
                                                        <input class="form-control" type="text" id="major_gubun" name="major_gubun" value="${member.major}" readonly>
                                                    </td>
                                                    <th class="table-secondary" style="width: 70px;">Email</th>
                                                    <td>
                                                        <input class="form-control" type="email" id="email" name="email" value="${member.email}" readonly>
                                                    </td>
                                                    <th class="table-secondary" style="width: 70px;">H.P</th>
                                                    <td>
                                                        <input class="form-control" type="text" id="phone" name="phone" value="${member.phone}" readonly>
                                                    </td>
                                                </tr>
                                            </thead>
                                        </table>
                                    </div>
                                    <div class="col-3 fw-bold">
                                        교과목정보
                                        <input type="hidden" id="detailId" name="detailId" value="">
                                    </div>
                                    <div class="col-12 mt-2">
                                        <table class="table table-bordered w-25">
                                            <thead>
                                                <tr class="align-middle text-center">
                                                    <th class="table-secondary" style="width: 120px;">교과목명</th>
                                                    <td>
                                                        <input class="form-control" type="text" id="lec_name" name="lec_name" value="" readonly>
                                                    </td>
                                                </tr>
                                            </thead>
                                        </table>
                                    </div>
                                    <div class="col-12">
                                        <table class="table table-bordered">
                                            <thead>
                                                <tr class="align-middle text-center">
                                                    <th class="table-secondary" style="width: 120px;">강좌목표</th>
                                                    <td>
                                                        <input class="form-control" type="text" id="plan_goal" name="plan_goal" value="" readonly>
                                                    </td>
                                                </tr>
                                            </thead>
                                        </table>
                                    </div>
                                    <div class="col-12">
                                        <table class="table table-bordered">
                                            <thead>
                                                <tr class="align-middle text-center">
                                                    <th class="table-secondary" style="width: 120px;">평가기준</th>
                                                    <th class="table-secondary" style="width: 120px;">중간고사</th>
                                                    <td>
                                                        <input class="form-control" type="number" id="plan_midterm_ratio" name="plan_midterm_ratio" value="" maxlength="2" readonly>
                                                    </td>
                                                    <th class="table-secondary" style="width: 120px;">기말고사</th>
                                                    <td>
                                                        <input class="form-control" type="number" id="plan_final_ratio" name="plan_final_ratio" value="" maxlength="2" readonly>
                                                    </td>
                                                    <th class="table-secondary" style="width: 120px;">과제</th>
                                                    <td>
                                                        <input class="form-control" type="number" id="plan_report_ratio" name="plan_report_ratio" value="" maxlength="2" readonly>
                                                    </td>
                                                    <th class="table-secondary" style="width: 120px;">출석</th>
                                                    <td>
                                                        <input class="form-control" type="number" id="plan_attendance" name="plan_attendance" value="" maxlength="2" readonly>
                                                    </td>
                                                </tr>
                                            </thead>
                                        </table>
                                    </div>
                                    <div class="col-12">
                                        <table class="table table-bordered">
                                            <thead>
                                                <tr class="align-middle text-center">
                                                    <th class="table-secondary" style="width: 120px;">강의운영방법</th>
                                                    <td>
                                                        <input class="form-control" type="text" id="plan_way" name="plan_way" value="" readonly>
                                                    </td>
                                                </tr>
                                            </thead>
                                        </table>
                                    </div>
                                    <div class="col-3 fw-bold">교재정보</div>
                                    <div class="col-12 mt-2">
                                        <table class="table table-bordered">
                                            <thead>
                                                <tr class="align-middle text-center">
                                                    <th class="table-secondary" style="width: 80px;">도서명</th>
                                                    <td>
                                                        <input class="form-control" type="text" id="book_name" name="book_name" value="" readonly>
                                                    </td>
                                                    <th class="table-secondary" style="width: 80px;">저자</th>
                                                    <td>
                                                        <input class="form-control" type="text" id="book_author" name="book_author" value="" readonly>
                                                    </td>
                                                    <th class="table-secondary" style="width: 80px;">출판사</th>
                                                    <td>
                                                        <input class="form-control" type="text" id="book_publisher" name="book_publisher" value="" readonly>
                                                    </td>
                                                    <th class="table-secondary" style="width: 90px;">출판연도</th>
                                                    <td>
                                                        <input class="form-control" type="text" id="book_year" name="book_year" value="" readonly>
                                                    </td>
                                                </tr>
                                            </thead>
                                        </table>
                                    </div>
                                    <div class="col-3 fw-bold">세부평가</div>
                                    <div class="col-12 mt-2">
                                        <table class="table table-bordered">
                                            <thead>
                                                <tr class="table-secondary lign-middle text-center">
                                                    <th style="width: 100px;">항목</th>
                                                    <th>내용</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                <tr class="align-middle text-center">
                                                    <td class="table-secondary" style="width: 100px;">중간/기말</td>
                                                    <td>
                                                        <textarea class="form-control w-100" name="plan_eval_detail1" id="plan_eval_detail1" cols="128" rows="5" maxlength="200" readonly></textarea>
                                                    </td>
                                                </tr>
                                                <tr class="align-middle text-center">
                                                    <td class="table-secondary" style="width: 100px;">과제</td>
                                                    <td>
                                                        <textarea class="form-control w-100" name="plan_eval_detail2" id="plan_eval_detail2" cols="128" rows="3" maxlength="200" readonly></textarea>
                                                    </td>
                                                </tr>
                                            </tbody>
                                        </table>
                                    </div>
                                    <div class="col-3 fw-bold">주차별수업계획</div>
                                    <div class="col-12 mt-2">
                                        <table class="table table-bordered">
                                            <tr class="align-middle text-center">
                                                <th class="table-secondary" style="width: 100px;">1주차</th>
                                                <td>
                                                    <input class="form-control" type="text" id="week_detail0" name="week_detail" value="" readonly>
                                                </td>
                                            </tr>
                                            <tr class="align-middle text-center">
                                                <th class="table-secondary" style="width: 100px;">2주차</th>
                                                <td>
                                                    <input class="form-control" type="text" id="week_detail1" name="week_detail" value="" readonly>
                                                </td>
                                            </tr> 
                                            <tr class="align-middle text-center">
                                                <th class="table-secondary" style="width: 100px;">3주차</th>
                                                <td>
                                                    <input class="form-control" type="text" id="week_detail2" name="week_detail" value="" readonly>
                                                </td>
                                            </tr> 
                                            <tr class="align-middle text-center">
                                                <th class="table-secondary" style="width: 100px;">4주차</th>
                                                <td>
                                                    <input class="form-control" type="text" id="week_detail3" name="week_detail" value="" readonly>
                                                </td>
                                            </tr> 
                                            <tr class="align-middle text-center">
                                                <th class="table-secondary" style="width: 100px;">5주차</th>
                                                <td>
                                                    <input class="form-control" type="text" id="week_detail4" name="week_detail" value="" readonly>
                                                </td>
                                            </tr> 
                                            <tr class="align-middle text-center">
                                                <th class="table-secondary" style="width: 100px;">6주차</th>
                                                <td>
                                                    <input class="form-control" type="text" id="week_detail5" name="week_detail" value="" readonly>
                                                </td>
                                            </tr> 
                                            <tr class="align-middle text-center">
                                                <th class="table-secondary" style="width: 100px;">7주차</th>
                                                <td>
                                                    <input class="form-control" type="text" id="week_detail6" name="week_detail" value="" readonly>
                                                </td>
                                            </tr> 
                                            <tr class="align-middle text-center">
                                                <th class="table-secondary" style="width: 100px;">8주차</th>
                                                <td>
                                                    <input class="form-control" type="text" id="week_detail7" name="week_detail" value="" readonly>
                                                </td>
                                            </tr> 
                                            <tr class="align-middle text-center">
                                                <th class="table-secondary" style="width: 100px;">9주차</th>
                                                <td>
                                                    <input class="form-control" type="text" id="week_detail8" name="week_detail" value="" readonly>
                                                </td>
                                            </tr> 
                                            <tr class="align-middle text-center">
                                                <th class="table-secondary" style="width: 100px;">10주차</th>
                                                <td>
                                                    <input class="form-control" type="text" id="week_detail9" name="week_detail" value="" readonly>
                                                </td>
                                            </tr> 
                                            <tr class="align-middle text-center">
                                                <th class="table-secondary" style="width: 100px;">11주차</th>
                                                <td>
                                                    <input class="form-control" type="text" id="week_detail10" name="week_detail" value="" readonly>
                                                </td>
                                            </tr> 
                                            <tr class="align-middle text-center">
                                                <th class="table-secondary" style="width: 100px;">12주차</th>
                                                <td>
                                                    <input class="form-control" type="text" id="week_detail11" name="week_detail" value="" readonly>
                                                </td>
                                            </tr> 
                                            <tr class="align-middle text-center">
                                                <th class="table-secondary" style="width: 100px;">13주차</th>
                                                <td>
                                                    <input class="form-control" type="text" id="week_detail12" name="week_detail" value="" readonly>
                                                </td>
                                            </tr> 
                                            <tr class="align-middle text-center">
                                                <th class="table-secondary" style="width: 100px;">14주차</th>
                                                <td>
                                                    <input class="form-control" type="text" id="week_detail13" name="week_detail" value="" readonly>
                                                </td>
                                            </tr> 
                                            <tr class="align-middle text-center">
                                                <th class="table-secondary" style="width: 100px;">15주차</th>
                                                <td>
                                                    <input class="form-control" type="text" id="week_detail14" name="week_detail" value="" readonly>
                                                </td>
                                            </tr> 
                                        </table>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <div>
                    <input type="hidden" id="getProfName" name="getProfName" value="${member.name}">
                </div>
                <!-- Spring Security CSRF TOKEN(csrf옵션 disabled이므로 사용되지 않는 값들이다.) -->
                <div>
                    <input type="hidden" id="page" name="page" value="0">
                    <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}" />
                </div>
                <div id="printPdf">
                    
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