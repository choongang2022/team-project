<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%-- <%@ include file="header.jsp"%> --%>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
   <title>휴/보강 신청</title>
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
   <script src="/js/dhJS/makeup.js" type="text/javascript"></script>
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
                  <i class="bi bi-bookmark-fill me-2"></i>학사관리 &gt; 강의관리 &gt; 휴/보강 신청</div>
               <!----- card content 내용 ------>
                  <div class="col-12 rounded-bottom overflow-auto bg-light p-5" style="min-height: 960px;">
                  
                  <h2>휴/보강 신청</h2><hr>
                  <div class="container-fluid justify-content-center text-center p-3">
					<div class="row ps-5">
						 <!-- 강의 목록 select box -->
						<select class="form-select w-25 mt-3" id="selLec" aria-label="Default select example" onchange="showOrdersList()">
							<c:forEach var="lecture" items="${lectureVOList }">
								<option value="${lecture.lec_id }">(${lecture.lec_typecode}${lecture.lec_id}) <b>${lecture.lec_name}</b>_${lecture.lec_type }</option>
							</c:forEach>
						</select>
					</div>
					<div class="row justify-content-center mt-3 p-4">
						<div class="col-12">
							<div class="text-start fw-bold h5 mb-3">강의일자</div>
							<div class="mt-2 mb-0" style="margin-right: 17px;">
								<table class="table table-bordered align-middle mb-0">
									<thead>
										<tr class="table-secondary align-middle">
											<th scope="col" rowspan="2" style="width: 16%">강의일자</th>
											<th scope="col" rowspan="2" style="width: 14%">요일</th>
											<th scope="col" rowspan="2" style="width: 14%">교시</th>
											<th scope="col" rowspan="2" style="width: 14%">진행상태</th>
											<th scope="col" colspan="3" style="width: 42%">보강내용</th>
										</tr>
										<tr class="table-secondary align-middle">
											<th scope="col" style="width: 14%">예정일자</th>
											<th scope="col" style="width: 14%">예정교시</th>
											<th scope="col" style="width: 14%">강의실</th>
										</tr>
									</thead>
								</table>
							</div>
							<div class="overflow-auto mt-0" style="height: 300px;">
								<table class="table table-bordered table-hover align-middle" id="ajaxAppend">
								</table>
							</div>
						</div>
					</div>
					<div class="row justify-content-center mt-3">
						<div class="col-8 d-flex flex-row">
							<div class="text-start fw-bold h5 me-3">휴/보강 내역</div>
							<input type="text" id="selectedLec" class="form-control form-control-sm border border-white" value="선택된 강의 없음" readonly style="height: 30px; width: 256px;">
							<input type="hidden" id="detailId" value="">
						</div>
						<div class="col-4 d-flex flex-row justify-content-end">
							<div class="btn btn-secondary" style="font-size: small; width: 78px;" onclick="updateOrders(0)">임시저장</div>
							<div class="btn btn-info ms-1" style="font-size: small; width: 78px;" onclick="updateOrders(1)">신청</div>
							<div class="btn btn-dark ms-1" style="font-size: small; width: 78px;" onclick="cancleOrders()">신청취소</div>
						</div>
					</div>
					<div class="row justify-content-center mt-2">
						<div class="col-9">
							<table class="table table-bordered">
								<tr class="align-middle">
									<th scope="col" class="table-secondary" style="width: 17%">
										휴강사유
									</th>
									<td>
										<input type="text" id="reason" class="form-control" placeholder="휴강 사유 입력란" value="">
									</td>
								</tr>
							</table>
						</div>
						<div class="col-3">
							<table class="table table-bordered">
								<tr class="align-middle">
									<th scope="col" class="table-secondary w-50" style="height: 55px;">
										진행상태
									</th>
									<td>
										<input type="text" class="form-control" id="status" value="강의미선택" readonly="readonly">
									</td>
								</tr>
							</table>
						</div>
					</div>
					<div class="row justify-content-center">
						<div class="col-12">
							<table class="table table-bordered">
								<tr class="align-middle">
									<th scope="col" class="table-secondary border-bottom border-secondary border-opacity-25" style="width: 13%">
										보강예정일
									</th>
									<td scope="col" colspan="2" style="width: 30%">
										<input id="lec_order_date" name="lec_order_date" class="form-control form-control-sm text-start" type="date" min="" required="required">
									</td>
									<th scope="col" class="table-secondary border-bottom border-secondary border-opacity-25" style="width: 13%">
										보강예정교시
									</th>
									<td scope="col" class="d-flex flex-row">
										<select id="lecTime1" name="time1" class=" form-select form-select-sm">
											<option selected value="">시작선택</option>
											<option value="1">1교시 (09:00-09:50)</option>
											<option value="2">2교시 (10:00-10:50)</option>
											<option value="3">3교시 (11:00-11:50)</option>
											<option value="4">4교시 (12:00-12:50)</option>
											<option value="5">5교시 (13:00-13:50)</option>
											<option value="6">6교시 (14:00-14:50)</option>
											<option value="7">7교시 (15:00-15:50)</option>
											<option value="8">8교시 (16:00-16:50)</option>
											<option value="9">9교시 (17:00-17:50)</option>
										</select>
										<select id="lecHour1" name="hour1" class=" form-select form-select-sm ms-2">
											<option value="">시간선택</option>
											<option value="1">1시간</option>
											<option value="2">2시간</option>
											<option value="3">3시간</option>
										</select>
									</td>
									<!-- <td scope="col">
									</td> -->
								</tr>
								<tr class="align-middle">
									<th scope="col" class="table-secondary" style="width: 13%">
										보강예정강의실
									</th>
									<th scope="col" class="table-secondary" style="width: 13%">
										강의동
									</th>
									<td scope="col">
										<select id="lec_building" name="lec_building" class="form-select form-select-sm me-0 " style=" margin-right: 0;" required="required">
											<option selected value="중앙동 ">중앙동</option>
											<option value="정보동">정보동</option>
											<option value="종합강의동">종합강의동</option>
										</select>
									</td>
									<th scope="col" class="table-secondary" style="width: 13%">
										호실
									</th>
									<td scope="col" colspan="1" class="w-25">
										<select id="lec_room" name="lec_room" class="form-select form-select-sm me-0 " style="margin: 0;" required="required">
											<option selected value="101호 ">101호</option>
											<option value="102호">102호</option>
											<option value="103호">103호</option>
											<option value="201호">201호</option>
											<option value="202호">202호</option>
											<option value="203호">203호</option>
										</select>
									</td>
								</tr>
							</table>
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