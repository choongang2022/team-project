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
		// select에 표시할 강의 목록 조회
		log.info("reportList 강의 list 조회 시작");
		List<Lecture> lectureList = dhprofessorReportService.findByProf(getMember.getMember().getName());
		model.addAttribute("lectureList", lectureList);
		return "/professor/report";
	}
	// test
	@GetMapping("/mainTest")
	public String testPage() {
		return "/professor/mainTest";
	}
	
	// 과제 리스트 조회
	@ResponseBody
	@PostMapping("/lecReportList")
	public Map<String, Object> lecReportList(@RequestParam("id") Long id, 
											 @RequestParam(required = false, defaultValue = "0", value="page") int page) {
		log.info("======lecReportList Start======");
		log.info(String.valueOf(id));
		log.info(Integer.toString(page));
		Map<String, Object> map = new HashMap<String, Object>();
		Long gubun = (long) 1; // 신청한 강의 테이블 구분값 (신청한 강의 : gubun = 1)
		// 과제List Paging
		int pageSize = 6;
		Pageable pageable = PageRequest.of(page, pageSize, Sort.by(Sort.Direction.ASC,"member.name"));
		// paging 가져오기
		Page<ApplicationLec> ApplicataionLecPaging = dhprofessorReportService.findPageByLecture_IdAndGubun(id, gubun, pageable);
		int totalPage = ApplicataionLecPaging.getTotalPages();
		int totalCount = (int) ApplicataionLecPaging.getTotalElements(); // 조회한 과제 List 총 개수(입력되지 않은 과제정보포함)(해당 강의를 듣는 학생 수)
		map.put("totalCount", totalCount);
		map.put("page" , page);
		map.put("pageSize", pageSize);
		map.put("totalPage", totalPage);
		map.put("ALP", ApplicataionLecPaging.getContent()); // 실질적으로 조회한 과제 목록 list 객체
		return map;
	}
	
	// 과제성적 입력 (과제테이블이 입력된 상태이므로 update로 입력한다.)
	@ResponseBody
	@PostMapping("/updateReportScore")
	public void updateReportScore(@RequestBody List<ReportUpdateDto> reportUpdateDtoList) {
		log.info("====updateReportScore start====");
		ArrayList<Integer> results = new ArrayList<Integer>();
		int result = 0;
		Long id = (long) 0;
		String score = "";
		String grade = "";
		for (ReportUpdateDto reportUpdateDto : reportUpdateDtoList) {
			if (reportUpdateDto != null) {
				id = (long) Integer.parseInt(reportUpdateDto.getId()); //view에서 String으로 보냈기 때문에 형변환 해준다.
				score = reportUpdateDto.getScore();
				grade = reportUpdateDto.getGrade();
				// update
				result = dhprofessorReportService.updateReportScore(id, score, grade);
				results.add(result);
			}
		}
		log.info("update Results : {}", results);
	}
	
	// 과제 파일 업로드 form (test용)

	@GetMapping("/uploadReportForm")
	public String uploadReportForm() {
		return "/professor/uploadReport";
	}
	
	// 과제 파일 업로드 (test용)
	
	@ResponseBody
	@PostMapping("/uploadReport")
	public String uploadReport(MultipartFile[] uploadFile) {
		String result = "";
		String userid = "student2";
		String uploadDirStr = "C:\\upload";
		String originalFileName = "";
		String dBSaveFile = "";
		File uploadDir = new File(uploadDirStr);
		if(!uploadDir.exists()) {
			uploadDir.mkdirs();
		}
		// local 저장소에 실제 파일 저장 및 DB에 파일이름,파일경로 저장
		for (MultipartFile multipartFile : uploadFile) {
			if(!multipartFile.isEmpty()) {
				UUID uuid = UUID.randomUUID();
				originalFileName = multipartFile.getOriginalFilename();
				String uploadFileName = uuid.toString() + "_" + originalFileName;
				dBSaveFile = uploadDir + "\\" + uploadFileName;
				File saveFile = new File(uploadDir, uploadFileName);
				try {
					//local storage 실제 파일 저장
					multipartFile.transferTo(saveFile);
					log.info("파일업로드 (local save) 성공");
					//DB 에 파일 이름, 파일저장경로 저장
					Report report = dhprofessorReportService.findByApplicationLec_Member_Userid(userid);
					report.setFileName(originalFileName);
					report.setFilePath(dBSaveFile);
					dhprofessorReportService.save(report);
					log.info("DB 저장 성공");
					result = "업로드 성공";
				} catch (Exception e) {
					log.error(e.getMessage());
					result = "업로드 실패 서버 에러";
				}
			}
		}
		return result;
	}
	
	// 모든 과제 파일 압축파일 생성
	@ResponseBody
	@PostMapping("/createZipAll/{id}")
	public void createZipAll(@PathVariable String id) {
		log.info("====createZipAll Start====");
		Long gubun = (long) 1; // 신청한 강의 테이블 구분값 (신청한 강의 : gubun = 1)
		Long idToFind = (long) Integer.parseInt(id);
		List<ApplicationLec> ApplicataionLecList = dhprofessorReportService.findByLecture_IdAndGubun(idToFind, gubun);
		List<String> fileList = new ArrayList<String>();
		Optional<Report> report = Optional.empty();
		String filePath = "";
		for (ApplicationLec applicationLec : ApplicataionLecList) {
			report = Optional.ofNullable(applicationLec.getReport());
			if(!report.isEmpty()) {
				filePath = report.get().getFilePath();
				if(filePath != null) {
					fileList.add(filePath);
					log.info("report filePath : {}", filePath);
				}
			}
		}
		String result = createZip(fileList);
		log.info(result);
	}
	
	
	// 선택된 과제 파일 압축파일 생성
	@ResponseBody
	@PostMapping("/createZipSel")
	public String createZipSel(@RequestParam(value = "fileList[]") List<String> fileList) {
		log.info("====createZip Start====");
		String result = "";
		result = createZip(fileList);
		return result;
	}
	


	// 압축파일 생성 method
	private String createZip(List<String> fileList) {
		log.info("압축 파일 생성 메소드 시작");
		String result = "";
		String tempPathStr  = "c:\\tempFolder";
		File   tempPathDir  = new File(tempPathStr);
		File   filePath     = new File("c:\\tempFolder\\report.zip");
		Path   filePathPath = Paths.get("c:\\tempFolder\\report.zip");
		// 임시 폴더에 report.zip 존재한다면 삭제
		if (filePath.exists()) {
			try {
				Files.delete(filePathPath);
			} catch (Exception e) {
				log.error("임시파일 삭제오류");
			}
		}
		
		// 압축파일 생성
		// 받은 파일 주소로 파일 list 생성
		List<File> files = new ArrayList<File>();
		for (int i = 0; i < fileList.size(); i++) {
			files.add(new File(fileList.get(i)));
		}
		// 파일 list로 압축파일 생성
		if(!tempPathDir.exists()) {
			tempPathDir.mkdirs();
		}
		File zipFile = new File(tempPathStr, "report.zip");
		byte[] buf = new byte[4896];
		
		try(ZipOutputStream out = new ZipOutputStream(new FileOutputStream(zipFile))) {
			for (File file : files) {
				try(FileInputStream in = new FileInputStream(file)) {
					ZipEntry ze = new ZipEntry(file.getName());
					out.putNextEntry(ze);
					
					int len;
					while((len = in.read(buf)) > 0) {
						out.write(buf, 0, len);
					}
					out.closeEntry();
					result = "압축 파일 생성 성공";
				} catch (Exception e) {
					log.error(e.getMessage());
				}
			}
		} catch (Exception e) {
		}
		return result;
	}
	
	// 압축파일 다운로드 요청
	@GetMapping("/downloadZip")
	public void downloadZip(HttpServletResponse response) throws Exception {
		log.info("downloadZip 시작");
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
		log.info("downloadOneFile 시작");
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
	
	//===================================과제 기능 끝===================================
}
