package com.oracle.choongangGroup.dongho.professor.report;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import javax.servlet.http.HttpServletResponse;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.multipart.MultipartFile;

import com.oracle.choongangGroup.changhun.JPA.Member;
import com.oracle.choongangGroup.dongho.auth.GetMember;
import com.oracle.choongangGroup.sh.domain.ApplicationLec;
import com.oracle.choongangGroup.sh.domain.Lecture;
import com.oracle.choongangGroup.sh.domain.Report;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

// 과제 기능 controller
@Slf4j
@Controller
@RequiredArgsConstructor
@RequestMapping("/professor")
public class DhProfessorReportController {
	private final DhProfessorReportService dhprofessorReportService;
	private final GetMember getMember;

	// 과제 리스트 페이지 요청
	@GetMapping("/reportList")
	public String reportList(Model model) {
		log.info("reportList 강의 list 조회 시작");
		Member member = getMember.getMember();
		model.addAttribute("member", member);
		// select에 표시할 강의 목록 조회
		List<Lecture> lectureList = dhprofessorReportService.findByProf(getMember.getMember().getName());
		model.addAttribute("lectureList", lectureList);
		return "/professor/report";
	}
	
	// 과제 리스트 조회
	@ResponseBody
	@PostMapping("/lecReportList")
	public Map<String, Object> lecReportList(@RequestParam("id") Long id, 
											 @RequestParam(required = false, defaultValue = "0", value="page") int page) {
		log.info("======lecReportList Start======");
		Map<String, Object> map = new HashMap<String, Object>();
		map = dhprofessorReportService.lecReportListPaging(id, page);
		return map;
	}
	
	// 과제성적 입력 (과제테이블이 입력된 상태이므로 update로 입력한다.)
	@ResponseBody
	@PostMapping("/updateReportScore")
	public void updateReportScore(@RequestBody List<ReportUpdateDto> reportUpdateDtoList) {
		log.info("====updateReportScore start====");
		ArrayList<Integer> results = new ArrayList<Integer>();
		
		results = dhprofessorReportService.updateReportScore(reportUpdateDtoList);
		log.info("update Results : {}", results);
	}
	
	// 과제 파일 업로드 form (test용)

	@GetMapping("/uploadReportForm")
	public String uploadReportForm() {
		return "/professor/uploadReport";
	}
	
	// 모든 과제 파일 압축파일 생성
	@ResponseBody
	@PostMapping("/createZipAll/{id}")
	public String createZipAll(@PathVariable String id) {
		log.info("====createZipAll Start====");
		Long idToFind = (long) Integer.parseInt(id);
		String result = dhprofessorReportService.createZipAll(idToFind);
		log.info(result);
		return result;
	}
	
	// 선택된 과제 파일 압축파일 생성
	@ResponseBody
	@PostMapping("/createZipSel")
	public String createZipSel(@RequestParam(value = "fileList[]") List<String> fileList) {
		log.info("====createZipSel Start====");
		String result = "";
		result = dhprofessorReportService.createZipSel(fileList);
		return result;
	}
	
	// 압축파일 다운로드 요청
	@GetMapping("/downloadZip")
	public void downloadZip(HttpServletResponse response) throws Exception {
		log.info("===downloadZip 시작===");
		String path = "C:\\tempFolder\\report.zip";
		try {
			File file = new File(path);
			response.setHeader("Content-Disposition", "attachment;filename=" + file.getName());
			log.info(file.getName());// 다운로드 되거나 로컬에 저장되는 용도로 쓰이는지를 알려주는 헤더
			FileInputStream fileInputStream = new FileInputStream(path); //파일 읽어오기
			OutputStream out = response.getOutputStream();
			
			int read = 0;
			byte[] buffer = new byte[1024];
			while ((read = fileInputStream.read(buffer)) != -1) { // 1024바이트씩 계속 읽으면서 outputStream에 저장, -1이 나오면 더이상 읽을 파일이 없음
				out.write(buffer, 0, read);
			}
		} catch (Exception e) {
			log.error("file download server error : " + e.getMessage());
		}
	}
	
	// 다운받을 과제파일이 1개일 경우 다운로드 method
	@GetMapping("/downloadOneFile")
	public void downloadOneFile(String filePath, HttpServletResponse response) {
		log.info("===downloadOneFile 시작===");
		try {
			File file = new File(filePath);
			response.setHeader("Content-Disposition", "attachment;filename=" + file.getName());
			log.info(file.getName());// 다운로드 되거나 로컬에 저장되는 용도로 쓰이는지를 알려주는 헤더
			FileInputStream fileInputStream = new FileInputStream(filePath); //파일 읽어오기
			OutputStream out = response.getOutputStream();
			
			int read = 0;
			byte[] buffer = new byte[1024];
			while ((read = fileInputStream.read(buffer)) != -1) { // 1024바이트씩 계속 읽으면서 outputStream에 저장, -1이 나오면 더이상 읽을 파일이 없음
				out.write(buffer, 0, read);
			}
		} catch (Exception e) {
			log.error("file download server error : " + e.getMessage());
		}
	}
	
}
