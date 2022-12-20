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
<!-- CSS -->
<link rel="stylesheet" href="/css/styles.css">
<link rel="stylesheet" href="/css/stylesLec.css">
<link rel="stylesheet" href="/css/bootstrap-datepicker.css">
<script src="https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.14.3/xlsx.full.min.js"></script>

<!--------- DATE PICKER --------->
<script src="https://code.jquery.com/jquery-3.2.1.js"></script>

<script  src="http://code.jquery.com/jquery-latest.min.js"></script>
<script type="text/javascript">
//강의 리스트 클릭시 강의 정보 띄우기
var CAL_STATUS = false;

function lecUpdate(id) {
	var scAplus = 0;
	var scA = 0;
	var scBplus = 0;
	var scB = 0;
	var scCplus = 0;
	var scC = 0;
	var scDplus = 0;
	var scD = 0;
	var scF = 0;
	var studCnt = 0;
	
	$.ajax({
		url 	: "lecFindById",
		data	: {"id" : id},
		dataType: 'text',
		success	: function(data){
			var lec = JSON.parse(data);
			$('#lecId').val(id);
			$('#lecGrade').html(lec.grade);
			$('#lecTypeCode').html(lec.type);
			$('#lecUnitScore').html(lec.unitScore);
			$('#lecMajor').html(lec.major);
			$('#chkScoreStatus').val(lec.scoreStatus);
			
			$.ajax({
				url 	: "lecScoreForm",
				data	: {"id" : id},
				dataType: 'text',
				success	: function(data){
					
					
					var html = "<tbody>";
					if(data.length > 0){
						$('#scoreTable > tbody').empty();
						$.each(JSON.parse(data).memList, function(index, item){
							html += "<tr>";
							html += "<th scope='row' class=' font09' style='text-align: center; vertical-align: middle;'>" + (index+1) + "</th>";
							html += "<th scope='row' class='zeroChkText text-danger font09' style='text-align: center; vertical-align: middle;'><div></div></th>";
						 	html += "<td style='text-align: center; vertical-align: middle;'>" + item.userid +"</td>"; 
						 	html += "<td style='text-align: center; vertical-align: middle;'>" + item.grade +"</td>"; 
						 	html += "<td style='text-align: center; vertical-align: middle;'>" + item.name +"</td>"; 
						 	html += "<td style='text-align: center; vertical-align: middle;'>" + item.major +"</td>"; 
						 	html += "<td style='text-align: center; vertical-align: middle;'>"; 
						 	html += "<input class='form-control onlynum zeroChk' type='text' id='attendanceScore" + index + "' value='0'></td>"; 
						 	html += "<td style='text-align: center; vertical-align: middle;'>"; 
						 	html += "<input class='form-control onlynum zeroChk' type='text' id='midtermScore" + index + "' value='0' ></td>"; 
						 	html += "<td style='text-align: center; vertical-align: middle;'>"; 
						 	html += "<input class='form-control onlynum zeroChk' type='text' id='finalsScore" + index + "' value='0' ></td>"; 
						 	html += "<td style='text-align: center; vertical-align: middle;'>"; 
						 	html += "<input class='form-control onlynum zeroChk' type='text' id='reportScore" + index + "' value='0' ></td>"; 
						 	
						 	html += "<td style='text-align: center; vertical-align: middle;'><div class='fw-bold' id='avgScore"+index +"'></div></td>"; 
						 	
						 	html += "<td style='text-align: center; vertical-align: middle;'>"; 
						 	html += "<input class='form-control' type='text' id='creditScore" + index + "' ></td>"; 
						 	html += "<td class='px-2' style='text-align: center; vertical-align: middle;'><div class='text-danger fw-bold'id='scoreF" + index + "' ></div>"; 
						 	html += "<input type='hidden' id='scoreId" + index + "'></td>"; 
							
						 	html += "</tr>"; 
						 	studCnt++;
						});
						html += "</tbody>";
						
						$('#lecStudCnt').text("( "+ studCnt +"명 )");
						
						$('#scoreTable > thead').after(html); 
						
						$.each(JSON.parse(data).grList, function(index, item){
							if(item != null) {
								var avgSco = ((Number(item.attendance)*0.2) + (Number(item.midterm)*0.3) 
							 				+ (Number(item.finals)*0.3) 	+ (Number(item.report)*0.2)).toFixed(2);
								
								$('#attendanceScore' + index).val(item.attendance);
								$('#midtermScore' + index).val(item.midterm);
								$('#finalsScore' + index).val(item.finals);
								$('#reportScore' + index).val(item.report);
								$('#creditScore' + index).val(item.credits); // 등급
								$('#avgScore' + index).text(avgSco);
								$('#scoreId' + index).val(item.id);
								if(item.credits == "F"){
									$('#scoreF' + index).text("재수강");
								}
								switch(item.credits) {
								case "A+" :
									scAplus++;
									break;
								case "A" :
									scA++;
									break;
								case "B+" :
									scBplus++;
									break;
								case "B" :
									scB++;
									break;
								case "C+" :
									scCplus++;
									break;
								case "C" :
									scC++;
									break;
								case "D+" :
									scDplus++;
									break;
								case "D" :
									scD++;
									break;
								case "F" :
									scF++;
									break;
								} //switch end
							}
						});
						
						$('#scoreCalTable > tbody').empty();

						var html2 = "<tbody>";
							html2 += "<tr>";
							html2 += "<th>배정인원</th>";
							html2 += "<td>" + scAplus + " 명</td>";
							html2 += "<td>" + scA + " 명</td>";
							html2 += "<td>" + scBplus + " 명</td>";
							html2 += "<td>" + scB + " 명</td>";
							html2 += "<td>" + scCplus + " 명</td>";
							html2 += "<td>" + scC + " 명</td>";
							html2 += "<td>" + scDplus + " 명</td>";
							html2 += "<td>" + scD + " 명</td>";
							html2 += "<td>" + scF + " 명</td>";
							html2 += "</tr>";  

							html2 += "<tr>";
							html2 += "<th>배정비율</th>";
							if(studCnt == 0) {
								html2 += "<td> 0.00%</td>";
								html2 += "<td> 0.00%</td>";
								html2 += "<td> 0.00%</td>";
								html2 += "<td> 0.00%</td>";
								html2 += "<td> 0.00%</td>";
								html2 += "<td> 0.00%</td>";
								html2 += "<td> 0.00%</td>";
								html2 += "<td> 0.00%</td>";
								html2 += "<td> </td>";
							} else {
								html2 += "<td>" + ((scAplus		/ (studCnt-scF)) * 100).toFixed(2) + " %</td>";
								html2 += "<td>" + ((scA 		/ (studCnt-scF)) * 100).toFixed(2) + " %</td>";
								html2 += "<td>" + ((scBplus 	/ (studCnt-scF)) * 100).toFixed(2) + " %</td>";
								html2 += "<td>" + ((scB 		/ (studCnt-scF)) * 100).toFixed(2) + " %</td>";
								html2 += "<td>" + ((scCplus 	/ (studCnt-scF)) * 100).toFixed(2) + " %</td>";
								html2 += "<td>" + ((scC 		/ (studCnt-scF)) * 100).toFixed(2) + " %</td>";
								html2 += "<td>" + ((scDplus		/ (studCnt-scF)) * 100).toFixed(2) + " %</td>";
								html2 += "<td>" + ((scD 		/ (studCnt-scF)) * 100).toFixed(2) + " %</td>";
								html2 += "<td> </td>";
							}
							html2 += "</tr>";  
							html2 += "</tbody>";
							
							console.log("scAplus ===>" + scAplus);
							console.log("studCnt ===>" + studCnt);
							
							$('#scoreCalTable > thead').after(html2); 
					}   
				}
			});
		}
	});
}

// 성적 넘기기
function lecScoreSave(){
	if(CAL_STATUS == false) {
		alert("등급계산이 안되었습니다. \n등급계산버튼을 클릭하세요.");
		return;
	}
	var inputData = [];
	$("#scoreTable > tbody tr" ).each(function(){
		inputData.push(
		{
			userid :	 $(this).find("td").eq(0).text(),
			attendance : $(this).find("td").eq(4).find("input").val(),
			midterm :	 $(this).find("td").eq(5).find("input").val(),
			finals : 	 $(this).find("td").eq(6).find("input").val(),
			report :	 $(this).find("td").eq(7).find("input").val(),
			credits :	 	 $(this).find("td").eq(9).find("input").val(),
			id :	 	 $(this).find("td").eq(10).find("input[type=hidden]").val(),
		});
	});
 	$.ajax({
 		method  : "post",
		url 	: "lecScoreSave",
		data	: {data  : JSON.stringify(inputData), 
				   lecId : $('#lecId').val()},
		dataType: 'json',
		traditional: true, //배열 넘길때 사용
		success	: function(data){
			console.log(data);
			 alert("성적이 저장되었습니다.");
			 CAL_STATUS = false;
			 lecUpdate($('#lecId').val());
		}
	}); 
}

// 숫자체크, 최대 100점 체크
$(document).ready(function(){
	$(document).on('propertychange change keyup paste input', '.onlynum', function() {
	    $(this).val($(this).val().replace(/[^0-9]/g, ""));
	    $(this).val(Number($(this).val()));
	    if(Number($(this).val()) > 100) {
	    	$(this).val(100);
	    }
	    if($(this).val() == "") {
	    	$(this).val(0);
	    }
	});
	
	/**********************/
	/****** 등급계산버튼 ******/
	/**********************/
	$('#lecScoreCal').click(function(){
		CAL_STATUS = true;
		scoreCalfun();
	});
	
	/***** 엑셀다운  ****/
	$('#scoreExcelDown').click(function(){
		var id = $('#lecId').val();
		if(id == null || id == '') {
			alert("먼저 강의를 선택해 주세요.");
			return false;
		}
		location.href="scoreExcelDown?id=" + id;
	});
	//성적마감버튼
	$('#lecScoreFinish').click(function(){
		if($('#chkScoreStatus').val() == '1'){
			alert("이미 마감완료된 강의입니다.");
			return false;
		}
		if(confirm("성적을 마감 하시겠습니까?") != true){
			return false;
		}
		$.ajax({
			url 	: "lecScoreFinish",
			data	: {id : $('#lecId').val()},
			dataType: 'text',
			success	: function(data){
				console.log(data);
				alert("성적이 마감이 완료 되었습니다.");
				window.location.reload();
			}
		});
	});
	
	/***** 엑셀업로드  ****/
	/******************/
	$("#excelFile").change(function(event){
		fnExcelUpload(event);
	});
});

function fnExcelUpload(event){
	var input = event.target;
	var reader = new FileReader();
	
	reader.onload = function() {
		var fileData = reader.result;
		var wb = XLSX.read(fileData,{type : 'binary'});
		wb.SheetNames.forEach(function(sheetName){
			var rowObj = XLSX.utils.sheet_to_json(wb.Sheets[sheetName]);
			
			$.each(rowObj, function(index, item){
				$("#scoreTable > tbody tr" ).each(function(){
					if(item.학번 == $(this).find("td").eq(0).text()) {
						if(typeof item.출결점수 == "undefined" || item.출결점수 == null || item.출결점수 == ""){
							$(this).find("td").eq(4).find("input").val(0);
						} else {
							$(this).find("td").eq(4).find("input").val(item.출결점수);
						}
						if(typeof item.중간점수 == "undefined" || item.중간점수 == null || item.중간점수 == ""){
							$(this).find("td").eq(5).find("input").val(0);
						} else {
							$(this).find("td").eq(5).find("input").val(item.중간점수);
						}
						if(typeof item.기말점수 == "undefined" || item.기말점수 == null || item.기말점수 == ""){
							$(this).find("td").eq(6).find("input").val(0);
						} else {
							$(this).find("td").eq(6).find("input").val(item.기말점수);
						}
						if(typeof item.과제점수 == "undefined" || item.과제점수 == null || item.과제점수 == ""){
							$(this).find("td").eq(7).find("input").val(0);
						} else {
							$(this).find("td").eq(7).find("input").val(item.과제점수);
						}
					}
				});
			});
		})
	};
	reader.readAsBinaryString(input.files[0]);
}

function scoreCalfun(){
	var inputData = [];
	
	var scoreFcnt = 0;
	var scAplus   = 0;
	var scA		  = 0;
	var scBplus	  = 0;
	var scB 	  = 0;
	var scCplus	  = 0;
	var scC		  = 0;
	var scDplus	  = 0;
	var scD		  = 0;
	var scF		  = 0;
	var studCnt	  = 0;
	
	$("#scoreTable > tbody tr" ).each(function(){
		var sum = ((Number( $(this).find("td").eq(4).find("input").val())*0.2) 
				 + (Number( $(this).find("td").eq(5).find("input").val())*0.3) 
				 + (Number( $(this).find("td").eq(6).find("input").val())*0.3) 
				 + (Number( $(this).find("td").eq(7).find("input").val())*0.2)).toFixed(2);
		var scoreF = "";
		var statusCheck = 0;
		studCnt++;
		
		if(Number( $(this).find("td").eq(4).find("input").val()) <= 20) {
			scoreF = "F";
			scoreFcnt++;
			
		}
		inputData.push(
		{
			userid :	 $(this).find("td").eq(0).text(),
			grade :	 	 $(this).find("td").eq(1).text(),
			attendance : $(this).find("td").eq(4).find("input").val(),
			midterm :	 $(this).find("td").eq(5).find("input").val(),
			finals : 	 $(this).find("td").eq(6).find("input").val(),
			report :	 $(this).find("td").eq(7).find("input").val(),
			avgScore :	 sum,
			credits :	 	 scoreF
		});
		
	});
	// 총합 성적이 높은 순으로 정렬 -> 등급구하기 위해서.
	inputData.sort(function (a, b) {
	    return b.avgScore - a.avgScore;
	});
	var rto = [ 0.1, 0.25, 0.5, 0.8, 0.9, 1.0 ];
	
 	for(var i = 0; i < inputData.length; i++) {
		if(inputData[i].credits != "F") {
			if (i < (inputData.length - scoreFcnt) * rto[0]) {	//2
				inputData[i].credits = "A+";
				scAplus++;
			} else if (i <  (inputData.length - scoreFcnt) * rto[1]) {	//3
				inputData[i].credits = "A";
				scA++;
			} else if (i <  (inputData.length - scoreFcnt) * rto[2]) {
				inputData[i].credits = "B+";
				scBplus++;
			} else if (i <  (inputData.length - scoreFcnt) * rto[3]) {
				inputData[i].credits = "B";
				scB++;
			} else if (i <  (inputData.length - scoreFcnt) * rto[4]) {
				inputData[i].credits = "C+";
				scCplus++;
			} else {
				inputData[i].credits = "C";
				scC++;
			}
		}
	} /* for문 end */ 
	
	inputData.sort(function (a, b) {
		if(a.grade > b.grade){
			return 1;
		}
		if(a.grade < b.grade){
			return -1;
		}
		if(a.userid > b.userid){
			return 1;
		}
		if(a.userid < b.userid){
			return -1;
		}
	});
	/* 값을 넣어주기 credits, 등급 */
	$("#scoreTable > tbody tr" ).each(function(index){
		$(this).find("td").eq(8).find("div").text(inputData[index].avgScore);
		$(this).find("td").eq(9).find("input").val(inputData[index].credits);
		
		if(inputData[index].credits != "F") {
			$(this).find("td").eq(10).find("div").text("");
		}
		if(inputData[index].credits == "F") {
			$(this).find("td").eq(10).find("div").text("재수강");
		}
		
		if(Number(inputData[index].avgScore) == 0) {
			$(this).find("th").eq(1).find("div").text("* 미입력");
			} else if(Number(inputData[index].attendance) == 0) {
				$(this).find("th").eq(1).find("div").text("* 출석점수");
			} else if(Number(inputData[index].midterm) == 0) {
				$(this).find("th").eq(1).find("div").text("* 중간점수");
			} else if(Number(inputData[index].finals) == 0) {
				$(this).find("th").eq(1).find("div").text("* 기말점수");
			} else if(Number(inputData[index].report) == 0) {
				$(this).find("th").eq(1).find("div").text("* 과제점수");
			} else{
				$(this).find("th").eq(1).find("div").text("");
			}
	});
	
	$('#scoreCalTable > tbody').empty();
	
	var html2 = "<tbody>";
	html2 += "<tr>";
	html2 += "<th>배정인원</th>";
	html2 += "<td>" + scAplus + " 명</td>";
	html2 += "<td>" + scA + " 명</td>";
	html2 += "<td>" + scBplus + " 명</td>";
	html2 += "<td>" + scB + " 명</td>";
	html2 += "<td>" + scCplus + " 명</td>";
	html2 += "<td>" + scC + " 명</td>";
	html2 += "<td>" + scDplus + " 명</td>";
	html2 += "<td>" + scD + " 명</td>";
	html2 += "<td>" + scoreFcnt + " 명</td>";
	html2 += "</tr>";  

	html2 += "<tr>";
	html2 += "<th>배정비율</th>";
	if(studCnt == 0) {
		html2 += "<td> 0.00%</td>";
		html2 += "<td> 0.00%</td>";
		html2 += "<td> 0.00%</td>";
		html2 += "<td> 0.00%</td>";
		html2 += "<td> 0.00%</td>";
		html2 += "<td> 0.00%</td>";
		html2 += "<td> 0.00%</td>";
		html2 += "<td> 0.00%</td>";
		html2 += "<td> </td>";
	} else {
		html2 += "<td>" + ((scAplus		/ (studCnt-scoreFcnt)) * 100).toFixed(2) + " %</td>";
		html2 += "<td>" + ((scA 		/ (studCnt-scoreFcnt)) * 100).toFixed(2) + " %</td>";
		html2 += "<td>" + ((scBplus 	/ (studCnt-scoreFcnt)) * 100).toFixed(2) + " %</td>";
		html2 += "<td>" + ((scB 		/ (studCnt-scoreFcnt)) * 100).toFixed(2) + " %</td>";
		html2 += "<td>" + ((scCplus 	/ (studCnt-scoreFcnt)) * 100).toFixed(2) + " %</td>";
		html2 += "<td>" + ((scC 		/ (studCnt-scoreFcnt)) * 100).toFixed(2) + " %</td>";
		html2 += "<td>" + ((scDplus		/ (studCnt-scoreFcnt)) * 100).toFixed(2) + " %</td>";
		html2 += "<td>" + ((scD 		/ (studCnt-scoreFcnt)) * 100).toFixed(2) + " %</td>";
		html2 += "<td> </td>";
	}
	html2 += "</tr>";  
	html2 += "</tbody>";
	
	console.log("scAplus ===>" + scAplus);
	console.log("studCnt ===>" + studCnt);
	
	$('#scoreCalTable > thead').after(html2); 
	
}



</script>
<style>
	table { 
		border-collapse: collapse; width: 100%;
	}
	 td { 
	background: #fff; }
	
	
	.tableFixHead  {
	  overflow: auto;
	  height: 130px;
	}
	
	.tableFixHead thead th {
	  position: sticky;
	  top: 0;
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
				<i class="bi bi-bookmark-fill me-2"></i>학사관리 &gt; 성적관리
			</div>
			<!----- card content 내용 ------>
			<div class="col-12 rounded-bottom overflow-auto bg-white p-5" style="min-height: 550px;">
				<h2>성적관리</h2>
				<hr class="mb-5">
				
				<div class="row mb-2">
					<div class="col-md-5">
						<div class="fw-bold" style="font-size: 1.2em; display: inline;">강의 리스트</div>
						<div class="font08" style="display: inline; float: right;">총 <b>${lecCnt}</b> 건</div>
							
						<div class="mt-2" style="height: 280px;border: solid 1px #bdbebe;">
						
						<input type="hidden" id="chkScoreStatus">
							<table class="table table-bordered table-hover table-sm font09" style="align:center;" id="lecTable">
								<thead class="table-secondary">
									<tr style="text-align: center;">
										<th scope="col" style="vertical-align: middle; width: 5%;">번호</th>
										<th scope="col" style="vertical-align: middle; width: 10%;">과목코드</th>
										<th scope="col" style="vertical-align: middle; width: 20%;">과목명</th>
										<th scope="col" style="vertical-align: middle; width: 8%;">성적입력</th>
									</tr>
								</thead>
								<tbody >
								<c:forEach var="lec" items="${lecList}">
									<c:set var="i" value="${i+1}"></c:set>
									<tr  onclick="lecUpdate(${lec.id})">
										<th class="text-center">${i}</th>
										<td class="text-center">${lec.typeCode}${lec.id}</td>
										<td class="text-center">${lec.name}</td>
									<c:choose>
										<c:when test="${lec.scoreStatus eq '0'}">
											<td class="text-center text-danger fw-bold">미입력</td>
										</c:when>
										<c:otherwise>
											<td class="text-center text-primary fw-bold">마감</td>
										</c:otherwise>
									</c:choose>
									</tr>
								</c:forEach>
								</tbody>
							</table>
						</div>
					</div>
					
					<div class="col-md-7">
						<div class="fw-bold" style="font-size: 1.2em;">성적입력정보</div>
						<div class="mt-2 py-3 px-4" style="height: 280px; border: solid 1px #bdbebe;">
							<div class="fw-bold item-start mb-2" style="display: inline; float: left;">강의정보</div>
						
							<table class="table font08 text-center table-bordered">
								<tr>
									<th class="table-secondary text-center" scope="col" style="vertical-align:middle; width:15%;">이수구분</th>
									<td class="p-2" id="lecTypeCode">
									</td>
									<th class="table-secondary me-0" scope="col" style="vertical-align:middle; width:10%;">전공</th>
									<td id="lecMajor">
										
									</td>
									<th class="table-secondary me-0" scope="col" style="vertical-align:middle; width:10%;">학점</th>
									<td id="lecUnitScore">
										
									</td>
									<th class="table-secondary me-0" scope="col" style="vertical-align:middle; width:10%;">학년</th>
									<td id="lecGrade">
										
									</td>
								</tr>
							</table>
						
							<div class="fw-bold item-start my-2" style="display: inline; float: left;">성적등급 분포 현황</div>
							
							<table class="table table font08 text-center" id ="scoreCalTable"style="border-color: gray;">
								<thead class="table-active">
									<tr class="table-active">
										<th scope="col"></th>
										<th scope="col">A+</th>
										<th scope="col">A0</th>
										<th scope="col">B+</th>
										<th scope="col">B0</th>
										<th scope="col">C+</th>
										<th scope="col">C0</th>
										<th scope="col">D+</th>
										<th scope="col">D0</th>
										<th scope="col">F</th>
									</tr>
								</thead>
							</table>
						</div>	
					</div>
			
					<br>
					<div><div class="my-5"></div>
						<div class="mt-2 fw-bold" style="font-size: 1.2em; display: inline;">강의학생&nbsp;&nbsp;<span class="text-danger font07" id="lecStudCnt">( 0명 )</span></div>
						<div class="mx-0 px-0" style="display: inline; float: right;">
							<button id="scoreExcelDown" type="button" style=" display: inline-block;" class="px-3 btn btn-secondary me-1 btn-sm"
									>엑셀 다운로드</button>
							<input type="file" id="excelFile" style="display: none;">
							<button id="scoreExcelUpload" onclick="onclick=document.all.excelFile.click()" type="button" style=" display: inline-block;" class="px-3 btn btn-dark me-4 btn-sm"
									>엑셀 업로드</button>
							<button id="lecScoreCal" type="button" style=" display: inline-block;" class="px-4 btn btn-primary btn-sm me-1"
									> 등급계산</button>
							<button id="lecScoreSave" onclick="lecScoreSave()" type="button" style=" display: inline-block" class="btn btn-dark btn-sm me-1 px-4"
									 > 임시저장 </button>
							<button id="lecScoreFinish" type="button" style=" display: inline-block" class="btn btn-danger btn-sm  px-4"
									> 성적마감 </button>
						</div>
						<div class="my-3"></div>
						
						<input type="hidden" id="lecId" name="id">
						<div class="scroll_wrap" style="height: 500px; overflow: scroll; overflow-x: hidden;">
							<table class="table font09 text-center " id="scoreTable">
								<thead class="table-secondary ">
									<tr style="text-align: center;">
										<th scope="col" style="vertical-align: middle; width: 5%;">번호</th>
										<th scope="col" style="vertical-align: middle; width: 8%;">상태</th>
										<th scope="col" style="vertical-align: middle; width: 8%;">학번</th>
										<th scope="col" style="vertical-align: middle; width: 4%;">학년</th>
										<th scope="col" style="vertical-align: middle; width: 10%;">이름</th>
										<th scope="col" style="vertical-align: middle; width: 13%;">전공</th>
										
										<th scope="col" style="vertical-align: middle; width: 6%;">출결<span class="font08">(20%)</span></th>
										<th scope="col" style="vertical-align: middle; width: 6%;">중간<span class="font08">(30%)</span></th>
										<th scope="col" style="vertical-align: middle; width: 6%;">기말<span class="font08">(30%)</span></th>
										<th scope="col" style="vertical-align: middle; width: 6%;">과제<span class="font08">(20%)</span></th>
										<th scope="col" style="vertical-align: middle; width: 6%;">총점</th>
										<th scope="col" style="vertical-align: middle; width: 6%;">등급</th>
										<th class="px-1" scope="col" style="vertical-align: middle; width: 8%;">&nbsp; 재수강여부 &nbsp;</th>
									</tr>
								</thead>
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