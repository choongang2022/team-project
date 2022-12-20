<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
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
<script src="https://code.jquery.com/jquery-3.4.1.js"></script>
<script  src="http://code.jquery.com/jquery-latest.min.js"></script>
<!-- CSS -->
<link rel="stylesheet" href="/css/styles.css">
<link rel="stylesheet" href="/css/stylesLec.css">

<script type="text/javascript">

///////강의 리스트 클릭시 강의 정보 띄우기 //////
function lecUpdate(id) {
	console.log("강의 클릭 ===> " + id);
	
	$.ajax({
		url 	: "lecFindById",
		data	: {"id" : id},
		dataType: 'text',
		success	: function(data){
			console.log("성공===> " + data );
			var lec = JSON.parse(data);
			console.log("==>" + lec.name);
			document.getElementById("lecName").value=lec.name;
			document.getElementById("lecGrade").value=lec.grade;
			document.getElementById("lecBuilding").value=lec.building;
			document.getElementById("lecRoom").value=lec.room;
			document.getElementById("lecDay1").value=lec.day1;
			document.getElementById("lecTime1").value=lec.time1;
			document.getElementById("lecHour1").value=lec.hour1;
			document.getElementById("lecDay2").value=lec.day2;
			document.getElementById("lecTime2").value=lec.time2;
			document.getElementById("lecHour2").value=lec.hour2;
			document.getElementById("lecMaxStud").value=lec.maxStud;
			document.getElementById("lecMaxCount").value=lec.maxCount;
			document.getElementById("lecTypeCode").value=lec.typeCode;
			document.getElementById("lecUnitScore").value=lec.unitScore;
			document.getElementById("lecYear").value=lec.year;
			document.getElementById("lecSemester").value=lec.semester;
			document.getElementById("lecMajor").value=lec.major;
			document.getElementById("lecId").value=lec.id;
			document.getElementById("lecStatus").value=lec.status;
			
		}
	});
}

//// 강의 삭제///////////
function lecDelete() {
	var id = document.getElementById("lecId").value;
	var status = document.getElementById("lecStatus").value;
	/* var status = document.getElementById("lecStatus").value; */
	console.log("강의 클릭 ===> " + id);
	console.log("강의 status ===> " + status);
 	if(status == '0') {
		alert("이미 승인된 강의입니다.\n삭제 할수 없습니다.");
		return false;
	} 
	if(confirm("삭제하시겠습니까?") == true){
		/* if(status  == '0') {
			alert("이미 승인된 강의입니다.\n삭제 할수 없습니다.")
			return false;
		} */
		$.ajax({
			url 	: "lecDelete",
			data	: {"id" : id},
			dataType: 'text',
			success	: function(data){
				window.location.reload();
			}
		});
	} else{
		return false;
	}
}

/////// 신규 클릭시 입력된 내용 날리기/////
function newLec(){
	window.location.reload();
}

////////강의검색///////////////////
function lecSearch() {
	var year = document.getElementById("searchYear").value;
	var semester = document.getElementById("searchSemester").value;
	var name = document.getElementById("searchName").value;
	console.log("검색하기");
	 // 체크박스 typeCode 값 넘기기
    var typeCode = "";
    $("input[name='typeCodeSearch']:checked").each(function(i) {
    	typeCode +=  $(this).val() + ",";
    });

    $.ajax({
		url 	: "lecSearch",
		data	: {"year"	  : year,
				   "semester" : semester,
				   "typeCode" : typeCode,
				   "name"	  : name
					},
		dataType: 'text',
		type:'post',
		success	: function(data){
			console.log(data);
			console.log(JSON.parse(data));
			var html = "";
			if(data.length > 0){
				$('#lecTable > tbody').empty();
				
				$.each(JSON.parse(data), function(index, item){
					html += "<tbody><tr>";
					html += "<th class='text-center'>" + (index+1) + "</th>";
				 	html += "<td class='text-center'>" + item.typeCode + item.id + "</td>"; 
					html += "<td class='text-center'>"+ item.prof +"</td>";
					html += "<td class='text-center'>" + item.name + "</td>";
					html += "<td class='text-center'>" + item.year + "</td>";
					html += "<td class='text-center'>" + item.semester + "</td>";
					html += "<td class='text-center'>" + item.major + "</td>";
					html += "<td class='text-center'>" + item.type +"</td>";
					html += "<td class='text-center'>" + item.unitScore + "</td>"; 
					if(item.status == '1') {
						html += "<td class='text-center text-danger fw-bold'>미승인</td>";
					} else if(item.status == '0') {
						html += "<td class='text-center text-primary fw-bold'>승인</td>";
					}
					html += "</tr>"; 
					html += "</tbody>";
				});
				
				console.log(html);
				 $('#lecTable > thead').after(html); 
			}
		}
	});
}
// 날짜 세팅. 년도, 학기
$(document).ready(function(){
	/* document.getElementById("sampleDiv").style.visibility ='hidden'; */
	var status = true;
	setDateBox();
	$('#lecHour1').change(function(){
		$('#hourCheckBox1 > div').empty();
		var lecUnitScore  = $('#lecUnitScore option:selected').val();
		var hour1 = parseInt($('#lecHour1 option:selected').val()); 
		var hour2 = parseInt($('#lecHour2 option:selected').val()); 
		if(isNaN(hour1)) {
			hour1 = 0;
		}
		if(isNaN(hour2)) {
			hour2 = 0;
		}
		var hourCnt = hour1 + hour2;	
		console.log("hourCnt ===" + hourCnt)
		var hourStatus = '';
		if(hourCnt < lecUnitScore) {
			hourStatus = "강의수업 시간  부족.<br>수업시간을 <b>"+ (lecUnitScore - hourCnt) + "</b> 시간 추가하세요.";
			status = false;
		} else if(hourCnt > lecUnitScore) {
			hourStatus = "강의수업 시간  초과.<br>수업시간을 <b>"+ (hourCnt - lecUnitScore) + "</b>시간 줄여주세요.";
			status = false;
		} else {
			status = true;
		}
		if(hour1 == lecUnitScore) {
			$('#lecDay2').val('');
			$('#lecTime2').val('');
			$('#lecHour2').val('');
			hourStatus = "";
		}
		
		var checkText = "<div class='font09 text-danger'>"+ hourStatus + "</div>"
		$('#hourCheckBox1').append(checkText);
	});
	
	$('#lecHour2').change(function(){
		$('#hourCheckBox1 > div').empty();
		var lecUnitScore  = $('#lecUnitScore option:selected').val();
		var hour1 =  parseInt($('#lecHour1 option:selected').val()); 
		var hour2 = parseInt($('#lecHour2 option:selected').val()); 
		if(isNaN(hour1)) {
			hour1 = 0;
		}
		if(isNaN(hour2)) {
			hour2 = 0;
		}
		var hourCnt = hour1 + hour2;
		var hourStatus = '';
		if(hourCnt < lecUnitScore) {
			hourStatus = "강의수업 시간  부족.<br>수업시간을 <b>"+ (lecUnitScore - hourCnt) + "</b> 시간 추가하세요.";
			status = false;
		} else if(hourCnt > lecUnitScore) {
			hourStatus = "강의수업 시간  초과.<br>수업시간을 <b>"+ (hourCnt - lecUnitScore) + "</b>시간 줄여주세요.";
			status = false;
		} else{
			status = true;
		}
		if(hour1 == lecUnitScore) {
			$('#lecDay2').val('');
			$('#lecTime2').val('');
			$('#lecHour2').val('');
			hourStatus = "";
		}
		var checkText = "<div class='font09 text-danger'>"+ hourStatus + "</div>"
		$('#hourCheckBox1').append(checkText);
	});

	$("#lecSaveBtn").click(function(){
		alert("강의명 : " + $("#lecName").val() + "\n저장되었습니다.");
		console.log("클릭");
		console.log("클릭" +  $("#lecName").val());
		
		if($("#lecTypeCode").val() == '') {
			alert("이수구분을 선택해주세요.");
			$('#lecTypeCode').focus();
			return false;
		}    
		if($("#lecMajor").val() == '') {
			alert("전공을 선택해주세요.");
			return false;
		} 
		if($("#lecMaxStud").val() == '') {
			alert("수강인원을 입력해주세요.");
			$('#lecMaxStud').focus();
			return false;
		}   
		if($("#lecName").val() == '') {
			alert("강의명을 입력해주세요.");
			$('#lecName').focus();
			return false;
		}   
 			//강의수가 학점이랑 다를 때
	 	if(status == false) {
			alert("강의시간을 확인하세요.");
			return false;
		}  
		
		if($("#lecDay1").val() == $("#lecDay2").val()) {
			alert("강의날짜가 겹칩니다.\n다른요일을 선택하세요");
			$('#lecDay2').focus();
			return false;
		}     

		if(Number($("#lecTime1").val()) + Number($("#lecHour1").val()) > 10) {
			alert("강의일1의 강의 종료시간을 확인해주세요.");
			$('#lecHour1').focus();
			return false;
		}
		if(Number($("#lecTime2").val()) + Number($("#lecHour2").val()) > 10) {
			alert("강의일2의 강의 종료시간을 확인해주세요.");
			$('#lecHour2').focus();
			return false;
		}
		
		/* 강의일, 수업시간, 강의식나 체크 */
 		if($("#lecDay1").val() == '') {
 			if($("#lecDay2").val() != ''){
 				alert("강의일1이 선택되지 않았습니다.\n강의일1부터 선택해주세요.");
 				$('#lecDay1').focus();
 				return false;
 			}
			alert("강의일1을 선택해주세요.");
			$('#lecDay1').focus();
			return false;
		}
		
		if($("#lecTime1").val() == '') {
			if($("#lecTime2").val() != ''){
 				alert("강의시간1이 선택되지 않았습니다.\n강의시간1부터 선택해주세요.");
 				$('#lecTime1').focus();
 				return false;
 			}
			alert("강의시간1을 선택해주세요!");
			$('#lecTime1').focus();
			return false;
		} 
		
		if($("#lecHour1").val() == '') {
			if($("#lecHour2").val() != ''){
 				alert("강의시간1의 수업시간이 선택되지 않았습니다.\n강의시간1의 수업시간부터 선택해주세요.");
 				$('#lecHour1').focus();
 				return false;
 			}
			alert("강의시간1의 수업시간을 선택해 주세요!");
			$('#lecHour1').focus();
			return false;
		} 
		if($("#lecHour1").val() != $("#lecUnitScore").val()) {
			if($("#lecDay2").val() == ''){
				alert("강의일2를 선택해 주세요!");
				$('#lecDay2').focus();
				return false;
			}
			if($("#lecTime2").val() == ''){
				alert("강의시간2를 선택해 주세요!");
				$('#lecTime2').focus();
				return false;
			}
			if($("#lecHour2").val() == ''){
				alert("강의시간2의 수업시간을 선택해 주세요!");
				$('#lecHour2').focus();
				return false;
			}
		}
		
		
		$("#lecSave").submit();
	});
	
	$("#lecTypeCode").click(function(){
		console.log("이수구분 클릭");
		/* 이수구분 : 교양 선택시 세팅 */
		if($("#lecTypeCode").val() == "C") {
			console.log("나는 교양");
			document.getElementById("lecMajor").value= "공통";
			document.getElementById("lecBuilding").value= "종합강의동";
			document.getElementById("lecGrade").value= "0";
			document.getElementById("lecUnitScore").value= "3";
		} else {
			console.log("나는 교양 아님");
			document.getElementById("lecMajor").value= "${member.major}";
			document.getElementById("lecBuilding").value= "중앙동";
			document.getElementById("lecGrade").value= "1";
			document.getElementById("lecUnitScore").value= "3";
		} 
	});
}); 

// 현재 날짜 기준 연도, 학기 세팅
function setDateBox() {
	var dt = new Date();
	var month = dt.getMonth() + 1;
	/* month = 7; //테스트용 setting */
	var com_year = dt.getFullYear();
	for(var i = (com_year+1); i >= (com_year-10); i--) {
	$('#searchYear').append("<option value='"+i+"'>"+i+"</option>");
	}
	// 9 10 11 12 1 2    // 3 4 5 6 7 8 
	if(month <= 2 || month >= 9) {
		$('#lecYear').val(com_year+1);
		$('#lecSemester').val("1");
	} else if(month >=3 || month <= 8){
		$('#lecYear').val(com_year);
		$('#lecSemester').val("2");
	} 
} 
</script>

<style>
	table { 
	
		/* border-collapse: collapse; width: 100%; */
	}
	th, td { 
	background: #fff; }
	
	.tableFixHead {
	  overflow: auto;
	  height: 170px;
	  background: #fff;
	}
	
	.tableFixHead thead th {
	  position: sticky;
	  top: 0;
	  margin-top: 0;
	}
</style>
	
</head>

<body id="body-pd"  style="background-color: rgb(214, 225, 237)">
	<jsp:include page="shortHeadrInfo.jsp"></jsp:include>
	
	<!-- side nav bar -->
	<jsp:include page="sideNavBar.jsp"></jsp:include>
	<!-- /side nav bar -->

	<!------- main content ------------>
	<div class="container-fluid w-100" style=" background-color: rgb(214, 225, 237);">
		<div class="row">
		
			<!------------- card header  컨텐츠 폼------------->
			<main class="col-9 h-100 w-100">
				<div class="row m-5">
				
					<!------------- 컨텐츠 경로 ------------->
					<div class="col-12 rounded-top text-white overflow-auto pt-2 fw-bold" style="background-color: rgb(39, 40, 70); height: 40px;">
						<i class="bi bi-bookmark-fill me-2"></i>학사관리 &gt; 강의개설 </div>
						
						<!----- card content 내용 ------>
						<div class="col-12 rounded-bottom overflow-auto bg-white p-5" style="min-height: 550px;">
						<h2>강의개설</h2><hr>
							<div class="mt-4  " >
								<div class="fw-bold item-start " style="display: inline; float: left;">개설강의 목록</div>
								<div class="font08" style="display: inline; float: right;">
									<span>총건수 <b class="text-danger">${lecCnt}</b>건 </span>
								</div>
							</div>
							<br>
							<div class="mt-4" style="display: inline;">
								<div class="mt-4 form-group col-md-5 px-0 text-left" style="display:inline; float:left;">
									<label  class="me-2 pe-0 font09">년도/학기</label>
									<select class="form-select-sm font09" name="year" id="searchYear" style="width: 15%;">
										<option class="font09" value="" selected>선택</option>
									</select>
									<span class="font09">년</span>
									
									<select class="ms-2 form-select-sm font09" name="semester" id="searchSemester" style="width: 12%">
										<option class="font09" value="" selected>선택</option>
										<option  class="font09" value="1">1학기</option>
										<option  class="font09" value="2">2학기</option>
									</select>
									
									<div class="form-check pe-0" style="display: inline;">
										<input type="checkbox" name="typeCodeSearch" value="M" >
										<label class="form-check-label font09">전필</label>
									</div>
									<div class="form-check ps-2  pe-0" style="display: inline;">
										<input type="checkbox" name="typeCodeSearch" value="S">
										<label class="form-check-label font09">전선</label>
									</div>
									<div class="form-check ps-2" style="display: inline;">
										<input type="checkbox" name="typeCodeSearch" value="C">
										<label class="form-check-label font09" >교양</label>
									</div>
								</div>
								
							<div class="mt-4 row col-md-7" style="float:left; display: inline;">
								<div class="input-group px-0 " style="width: 40%;">
									<label class="form-label me-2 mb-0 align-self-center font09">강의명</label>
									<input class="form-control form-sm rounded-1" type="text" id="searchName" name="name"
											aria-describedby="button-search" style="height: 31px;">
			
									<button class="btn btn-secondary btn-sm" id="button-search" type="button"
											onclick="lecSearch()">검색</button>
								</div>
							</div>
			
							<br>
							<div class="mt-4 mb-2 form-group mx-0 font09" style="display: inline;">
									<!-- <p class="fw-bold ">개설강의 목록</p> -->
							
								<div class="mx-0 px-0 text-end">
									<button type="button" style="width: 8%; display: inline;" class="btn btn-primary btn-sm me-1"
											onclick="newLec()">신규</button>
									<button type="button" id="lecSaveBtn" style="width: 8%; display: inline;" class="btn btn-dark btn-sm me-1"
											>저장</button>
									<button type="button" style="width: 8%; display: inline;" class="btn btn-danger btn-sm"
									        onclick="lecDelete()">삭제</button>
								</div>
							</div>
				
							<br>
			 				<div class="tableFixHead font08 mx-0" style="width:100%; border-bottom: 1px; background: solid 1px #bdbdbd; /* border-collapse: collapse; border: solid 1px #bdbdbd; */" >
								<table class="table table-bordered table-hover table-sm"  id="lecTable">
									<thead class="table-secondary py-1">
										<tr style="text-align: center;">
											<th scope="col" style="vertical-align: middle; width: 4%;">순번</th>
											<th scope="col" style="vertical-align: middle; width: 10%;">강의번호</th>
											<!-- <th scope="col" style="vertical-align: middle; width: 10%;">교수명</th> -->
											<th scope="col" style="vertical-align: middle;">강의명</th>
											<th scope="col" style="vertical-align: middle; width: 7%;">개설년도</th>
											<th scope="col" style="vertical-align: middle; width: 7%;">학기</th>
											<th scope="col" style="vertical-align: middle; width: 20%;">전공</th>
											<th scope="col" style="vertical-align: middle; width: 7%;" >이수구분</th>
											<th scope="col" style="vertical-align: middle; width: 7%;">학점</th>
											<th scope="col" style="vertical-align: middle; width: 7%;">승인여부</th>
										</tr>
									</thead>
									
									<c:forEach var="lec" items="${lecList}">
										<tbody id="FindLec">
											<c:set var="i" value="${i+1}"></c:set>
											<tr onclick="lecUpdate(${lec.id})">
												<th class="text-center">${i }</th>
												<td class="text-center">${lec.typeCode}${lec.id}</td>
												<%-- <td class="text-center">${lec.prof}</td> --%>
												<td class="text-center">${lec.name}</td>
												<td class="text-center">${lec.year}</td>
												<td class="text-center">${lec.semester}</td>
												<td class="text-center">${lec.major}</td>
												<td class="text-center">${lec.type}</td>
												<td class="text-center">${lec.unitScore}</td>
												<c:choose>
												<c:when test="${lec.status eq '1'}">
													<td class="text-center text-danger fw-bold">미승인</td>
												</c:when>
												<c:otherwise>
													<td class="text-center text-primary fw-bold">승인</td>
												</c:otherwise>
												</c:choose>
											</tr>
										</tbody>
									</c:forEach>
								</table>
							</div>
							<br>
							<div class="mt-2 fw-bold ">개설강의 상세정보</div>
							<br>
							
							<form id="lecSave" action="/professor/lecSave" method="post">
							
								<input type="hidden" id="lecId" name="id">
								<input type="hidden" id="lecStatus" name="status" value="1"> <!-- 승인전 강의상태 :1 -->
								<input type="hidden" id="lecStudCount" name="studCount" value="0"> <!-- 강의를 신청한 학생수 :0 -->
								<input type="hidden" id="lecScoreStatus" name="scoreStatus" value="0"> <!-- 점수미입력 :0 -->
								
								<table class="table font09 text-center">
									<tr><th class="table-secondary text-center " scope="col" style="width: 9%; vertical-align:middle;">년도</th>
										<td class="p-2" style="width:16%;">
											<input class="form-control text-center mx-0 form-inline form-control-sm " type="text"  
													id="lecYear" name="year" readonly="readonly">
										</td>
										<th class="table-secondary me-0" scope="col" style="vertical-align:middle; width: 9%;">학기</th>
										<td>
											<input class="form-control text-center mx-0 form-inline form-control-sm " type="text"  
													id="lecSemester" name="semester" readonly="readonly">
											<!-- 
											<select id="lecSemester" name="semester" class="form-select form-select-sm me-0" >
												<option value="1" selected>1</option>
												<option value="2">2</option> -->
											</select>
										</td>
										<th class="table-secondary" scope="col" style="width: 9%; vertical-align:middle;">총시수</th>
										<td>
											<select id="lecMaxCount" name="maxCount" class="form-select form-select-sm me-0" style="margin: 0;">
												<option value="14">14</option>
												<option selected value="15">15</option>
											</select>
										</td>
										<th class="table-secondary" scope="col" style="width: 9%; vertical-align:middle;">학점</th>
										<td>
											<select id="lecUnitScore" name="unitScore" class="form-select form-select-sm me-0 " style="margin: 0;">
											<!-- <option selected value="1">1 학점</option> -->
											<option value="2">2 학점</option>
											<option selected value="3">3 학점</option>
										</select>
										</td>
									</tr>
									
									<tr>
										<th class="table-secondary text-center" scope="col" style="width: 9%; vertical-align:middle;">이수구분</th>
										<td class="p-2">
											<select id="lecTypeCode" name="typeCode" class="form-select form-select-sm me-0 " style="margin-left: 0;">
												<option value="">선택</option>
												<option value="M">전필</option>
												<option value="S">전선</option>
												<option value="C">교양</option>
											</select>
										</td>
										<th class="table-secondary me-0" scope="col" style="vertical-align:middle; width: 9%;">전공</th>
										<td>
											<select id="lecMajor" name="major" class="form-select form-select-sm " style="margin: 0;">
												<option value="" >선택</option>
												<option value="공통" >공통</option>
												<option value="컴퓨터공학과">컴퓨터공학과</option>
												<option value="소프트웨어과">소프트웨어과</option>
												<option value="AI학과">AI학과</option>
												<option value="경영학과">경영학과</option>
										</select>
										</td>
										<th class="table-secondary" scope="col" style="width: 9%; vertical-align:middle;">대상학년</th>
										<td  style="width:16%;">
											<select id="lecGrade" name="grade" class="form-select form-select-sm me-0 " style="margin: 0;">
												<option value="1">1 학년</option>
												<option value="2">2 학년</option>
												<option value="3">3 학년</option>
												<option value="4">4 학년</option>
												<option value="0">공통</option>
											</select>
										</td>
										<th class="table-secondary" scope="col" style="width: 9%; vertical-align:middle;">수강인원</th>
										<td>
											<input id="lecMaxStud" name="maxStud" class="form-control form-control-sm text-start" type="text" >
										</td>
									</tr>
				
									
									<tr>
										<th class="table-secondary text-center" scope="col" style="width: 9%; vertical-align:middle;">강의명</th>
										<td colspan="3" class="p-2" style="width:16%;">
											<input id="lecName" name="name" class="form-control form-control-sm text-start " 
												type="text" placeholder="개설할 강의명을 입력해주세요" >
										</td>
										<th class="table-secondary me-0" scope="col" style="vertical-align:middle;">건물명</th>
										<td>
											<select id="lecBuilding" name="building" class="form-select form-select-sm me-0 " style=" margin-right: 0;">
												<option value="중앙동">중앙동</option>
												<option value="정보동">정보동</option>
												<option value="종합강의동">종합강의동</option>
											</select>
										</td>
										<th class="table-secondary" scope="col" style="width: 9%; vertical-align:middle;">호수</th>
										<td>
											<select id="lecRoom" name="room" class="form-select form-select-sm me-0 " style="margin: 0;">
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
									
									
									<table class="table font09 text-center">
										<tr>
											<th class="table-secondary text-center" scope="col" style="width: 9%; vertical-align:middle;">강의일1</th>
											<td class="p-2">
												<select id="lecDay1" name="day1" class="form-select form-select-sm me-0 " 
														style="margin: 0;">
													<option value="" selected>선택</option>
													<option value="월">월요일</option>
													<option value="화">화요일</option>
													<option value="수">수요일</option>
													<option value="목">목요일</option>
													<option value="금">금요일</option>
												</select>
											</td>
											<th class="table-secondary me-0" scope="col" style="vertical-align:middle;width: 9%;">강의시간1</th>
											<td style=" margin-right: 0;">
												<select id="lecTime1" name="time1" class=" form-select form-select-sm">
													<option selected value="">선택</option>
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
											</td>
											<td style=" margin-right: 0;">
												<select id="lecHour1" name="hour1" class=" form-select form-select-sm">
													<option value="">시간선택</option>
													<option value="1">1시간</option>
													<option value="2">2시간</option>
													<option value="3">3시간</option>
												</select>
											</td>
				
											<td style="width: 20%; margin-right: 0;" id="hourCheckBox1"><%-- ${lecDayTimeText} --%>
												<!-- <div class="font09 text-danger" style="vertical-align:middle;" id="hourCheckBox1"></div> -->
											</td>
										</tr>
										
										<tr>
											<th class="table-secondary text-center" scope="col" style="width: 9%; vertical-align:middle;">강의일2</th>
											<td class="p-2">
												<select id="lecDay2" name="day2" class="form-select form-select-sm me-0 " 
														style="margin: 0;">
													<option value="" selected>선택</option>
													<option value="월">월요일</option>
													<option value="화">화요일</option>
													<option value="수">수요일</option>
													<option value="목">목요일</option>
													<option value="금">금요일</option>
												</select>
											</td>
											<th class="table-secondary me-0" scope="col" style="vertical-align:middle; width: 9%;">강의시간2</th>
											<td style=" margin-right: 0;">
												<select id="lecTime2" name="time2" class=" form-select form-select-sm" >
													<option selected value="">선택</option>
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
											</td>
											
											<td style=" margin-right: 0;">
												<select id="lecHour2" name="hour2" class=" form-select form-select-sm">
													<option selected value="">시간선택</option>
													<option value="1">1시간</option>
													<option value="2">2시간</option>
													<option value="3">3시간</option>
												</select>
											</td>
											<td style="width: 20%; margin-right: 0;"><%-- ${lecDayTimeText} --%>
												<div class="font09 text-danger" style="vertical-align:middle;" id="hourCheckBox2"></div>
											</td>
										</tr>
									</table>
							</form>	
							
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