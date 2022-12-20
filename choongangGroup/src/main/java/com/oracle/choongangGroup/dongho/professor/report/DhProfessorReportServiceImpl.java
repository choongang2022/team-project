package com.oracle.choongangGroup.dongho.professor.report;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import javax.transaction.Transactional;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

import com.oracle.choongangGroup.dongho.professor.repository.DhProfessorAppLecRepository;
import com.oracle.choongangGroup.dongho.professor.repository.DhProfessorLecRepository;
import com.oracle.choongangGroup.dongho.professor.repository.DhProfessorReportRepository;
import com.oracle.choongangGroup.sh.domain.ApplicationLec;
import com.oracle.choongangGroup.sh.domain.Lecture;
import com.oracle.choongangGroup.sh.domain.Report;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@Transactional
@RequiredArgsConstructor
public class DhProfessorReportServiceImpl implements DhProfessorReportService {
	private final DhProfessorLecRepository lr;
	private final DhProfessorReportRepository rr;
	private final DhProfessorAppLecRepository alr;
	
	@Override
	public List<Lecture> findByProf(String profName) {
		return lr.findByProf(profName);
	}

	@Override
	public ArrayList<Integer> updateReportScore(List<ReportUpdateDto> reportUpdateDtoList) {
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
				try {
					log.info("service params : id : {}, score : {}, garde : {}", id, score, grade);
					result = rr.updateReportScore(id, score, grade);
					results.add(result);
					
				} catch (Exception e) {
					result = 0;
				}
			}
		}
		return results;
	}

	@Override
	public String createZipAll(Long idToFind) {
		log.info("====createZipAll Start====");
		Long gubun = (long) 2; // 신청한 강의 테이블 구분값 (신청한 강의 : gubun = 1)
		List<ApplicationLec> ApplicataionLecList = alr.findByLecture_IdAndGubun(idToFind, gubun);
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
		if (fileList.size() == 0) {
			return "과제 파일이 존재하지 않습니다.";
		}
		return createZipMethod(fileList);
	}

	@Override
	public String createZipSel(List<String> fileList) {
		return createZipMethod(fileList);
	}

	@Override
	public Map<String, Object> lecReportListPaging(Long id, int page) {
		Map<String, Object> map = new HashMap<String, Object>();
		Long gubun = (long) 2; // 신청한 강의 테이블 구분값 (신청한 강의 : gubun = 1)
		// 과제List Paging
		int pageSize = 6;
		Pageable pageable = PageRequest.of(page, pageSize, Sort.by(Sort.Direction.ASC,"member.name"));
		// paging 가져오기
		Page<ApplicationLec> ApplicataionLecPaging = alr.findPageByLecture_IdAndGubun(id, gubun, pageable);
		int totalPage  = ApplicataionLecPaging.getTotalPages();
		int totalCount = (int) ApplicataionLecPaging.getTotalElements(); // 조회한 과제 List 총 개수(입력되지 않은 과제정보포함)(해당 강의를 듣는 학생 수)
		map.put("totalCount", totalCount);
		map.put("page" , page);
		map.put("pageSize", pageSize);
		map.put("totalPage", totalPage);
		map.put("ALP", ApplicataionLecPaging.getContent()); // 실질적으로 조회한 과제 목록 list 객체
		return map;
	}
	
	// 압축파일 생성 method
	private String createZipMethod(List<String> fileList) {
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

}
