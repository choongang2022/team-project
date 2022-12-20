package com.oracle.choongangGroup.dongho.professor.lecturePlan;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;
import javax.transaction.Transactional;

import org.springframework.stereotype.Service;
import org.springframework.util.ResourceUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.multipart.MultipartRequest;

import com.oracle.choongangGroup.dongho.professor.lecturePlan.dto.LecPlanDto;
import com.oracle.choongangGroup.dongho.professor.lecturePlan.dto.LecPlanLecDto;
import com.oracle.choongangGroup.dongho.professor.lecturePlan.dto.LecPlanWeekDto;
import com.oracle.choongangGroup.dongho.professor.lecturePlan.dto.PlanPdfDto;
import com.oracle.choongangGroup.dongho.professor.mappers.LecPlanMapper;
import com.oracle.choongangGroup.dongho.professor.mappers.LecPlanWeekMapper;
import com.oracle.choongangGroup.dongho.professor.mappers.LectureMapper;
import com.oracle.choongangGroup.sh.domain.Report;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.sf.jasperreports.engine.JasperCompileManager;
import net.sf.jasperreports.engine.JasperExportManager;
import net.sf.jasperreports.engine.JasperFillManager;
import net.sf.jasperreports.engine.JasperPrint;
import net.sf.jasperreports.engine.JasperReport;
import net.sf.jasperreports.engine.data.JRBeanCollectionDataSource;

@Slf4j
@Service
@Transactional
@RequiredArgsConstructor
public class DhLecPlanServiceImpl implements DhProLecPlanService{
	private final LectureMapper     lectureMapper;
	private final LecPlanMapper     lecPlanMapper;
	private final LecPlanWeekMapper lecPlanWeekMapper;
	
	@Override
	public List<LecPlanLecDto> findByProfNameAndYearAndSemester(String profName, String year, String semester, String lecStatus) {
		return lectureMapper.findByProfNameAndYearAndSemester(profName, year, semester, lecStatus);
	}

	@Override
	public LecPlanDto findLecPlanByLecId(Long id) {
		log.info("findLecPlanByLecId select start");
		return lecPlanMapper.findByLecId(id);
	}

	@Override
	public List<LecPlanWeekDto> findLecPlanWeekByLecId(Long id) {
		log.info("findLecPlanWeekByLecId select start");
		return lecPlanWeekMapper.findByLecId(id);
	}

	@Override
	public int insertPlan(LecPlanDto lecPlanDto) {
		int resultPlan = lecPlanMapper.insertPlan(lecPlanDto);
		System.out.println(resultPlan);
		return resultPlan;
	}

	@Override
	public Object insertWeek(List<Map<Object, Object>> planWeekArray) {
		int resultWeek = lecPlanWeekMapper.insertWeek(planWeekArray);
		return resultWeek;
	}

	@Override
	public Optional<LecPlanDto> findByLecIdWithOptional(Long lec_id) {
		
		return lecPlanMapper.findByLecIdWithOptional(lec_id);
	}

	@Override
	public int updatePlan(LecPlanDto lecPlanDto) {
		return lecPlanMapper.updatePlan(lecPlanDto);
	}

	@Override
	public int updateWeek(List<Map<Object, Object>> planWeekArray) {
		return lecPlanWeekMapper.updateWeek(planWeekArray);
	}

	@Override
	public int deletePlanAndLec(Long lec_id) {
		int result = 0;
		Map<String, Object> map = new HashMap<>();
		int check = 0; // plan table 데이터가 없다면 0, 있다면 1
		String lecPlanFilePath = lectureMapper.findFilePathByLecId(lec_id);
		Long lecPlanLecId = isExistPlan(lec_id);
		System.out.println(lecPlanFilePath);
		System.out.println(lecPlanLecId);
		if (lecPlanLecId == null && lecPlanFilePath == null) {
			log.info("삭제할 lecPlan, lecPlanFile 없음");
			result = -2;
		} else if(lecPlanLecId == null && lecPlanFilePath != null) {
			File toDelFile = new File(lecPlanFilePath);
			if(toDelFile.exists()) {
				toDelFile.delete();
				check = 0;
				map.put("lec_id", lec_id);
				map.put("check", check);
				System.out.println(map);
				int resultDelete = lecPlanMapper.deletePlanAndLec(map);
				log.info("업로드했던 파일 존재! 파일삭제 성공 : {}", toDelFile);
				result = -3;
			}
		} else {
			if(lecPlanLecId != null && lecPlanFilePath != null) {
				System.out.println(1);
				File toDelFile = new File(lecPlanFilePath);
				if(toDelFile.exists()) {
					toDelFile.delete();
					check = 1;
					map.put("lec_id", lec_id);
					map.put("check", check);
					System.out.println(map);
					log.info("업로드했던 파일 존재! 파일삭제 성공 : {}", toDelFile);
				}
				result = lecPlanMapper.deletePlanAndLec(map);
			} else {
				System.out.println(2);
				check = 2;
				map.put("lec_id", lec_id);
				map.put("check", check);
				result = lecPlanMapper.deletePlanAndLec(map)+4;
				System.out.println(result);
			}
		}
		return result;
	}

	@Override
	public String generatePdf(PlanPdfDto planPdfDto, HttpServletRequest request) throws Exception {
		log.info("===generatePdf Start===");
		OutputStream outputStream = null;
		String filePath = "";
		String fileRealName = "";
		List<PlanPdfDto> dtoList = new ArrayList<>();
		dtoList.add(planPdfDto);
		try {
			URL getPath = this.getClass().getClassLoader().getResource(""); // jasper 템플릿 읽어오기 위한 경로
			String sUrl = request.getServletContext().getRealPath("/"); // 서버에 저장할 경로
			
			File file = ResourceUtils.getFile(getPath + "jasperReport/lecPlanPdf.jrxml"); // 템플릿 읽기
			JasperReport jasperReport = JasperCompileManager.compileReport(file.getAbsolutePath());
			JRBeanCollectionDataSource dataSource = new JRBeanCollectionDataSource(dtoList); // 데이터 넘기기
			Map<String, Object> parameters = new HashMap<>(); // 파라미터 넘기기(실제로는 넘기지 않음)
			ArrayList<?> dataList = (ArrayList<?>) dataSource.getData();
			for (int i = 0; i < dataList.size(); i++) {
				parameters.put(i+ "", dataList.get(i));
			}
			
			JasperPrint jasperPrint = JasperFillManager.fillReport(jasperReport, parameters, dataSource);
			
			fileRealName = "lecPlanPdf_" + System.currentTimeMillis(); // 리턴할 파일이름
			filePath = sUrl + "pdf/" + fileRealName + ".pdf"; // 서버 저장하기 위한 파일 경로
			
			String uploadDirStr = sUrl + "pdf/";
			File uploadDir = new File(uploadDirStr);
			//임시파일 업로드 디렉토리가 존재하지 않으면 생성
			if(!uploadDir.exists()) {
				log.info("uploadFolder가 존재하지 않으므로 폴더생성");
				uploadDir.mkdirs();
			}
			//이전에 임시로 생성되었던 pdf 파일 삭제
			File[] files = uploadDir.listFiles();
			for (File fileInUpload : files) {
				log.info("예전 임시 pdf 파일삭제 : {}", fileInUpload);
				fileInUpload.delete();
			}
			outputStream = new FileOutputStream(new File(filePath)); // 서버에 pdf 저장
			JasperExportManager.exportReportToPdfStream(jasperPrint, outputStream);
			
			outputStream.flush();
			outputStream.close();
		} catch (Exception e) {
			log.error(e.toString());
		} finally {
			if (outputStream != null) {
				outputStream.flush();
				outputStream.close();
			}
		}
		return fileRealName;
	}

	@Override
	public int uploadPlanFile(String lec_id, MultipartFile[] multipartFiles) {
		HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
		Long long_lec_id = (long) Integer.parseInt(lec_id);
		int result = 0;
		String originalFileName = "";
		String dBSaveFile = "";
		String sUrl = request.getServletContext().getRealPath("/");
		String uploadDirStr = sUrl + "/upload/dh/uploadPlan/";
		File uploadDir = new File(uploadDirStr);
		if(!uploadDir.exists()) {
			uploadDir.mkdirs();
		}
		//기존 업로드 파일 삭제
		String lecPlanFilePath = lectureMapper.findFilePathByLecId(long_lec_id);
		if(lecPlanFilePath != null) {
			File toDelFile = new File(lecPlanFilePath);
			if(toDelFile.exists()) {
				toDelFile.delete();
				log.info("업로드했던 파일 존재! 파일삭제 성공 : {}", toDelFile);
			}
		}
		// local 저장소에 실제 파일 저장 및 DB에 파일이름,파일경로 저장
		for (MultipartFile multipartFile : multipartFiles) {
			if(!multipartFile.isEmpty()) {
				UUID uuid = UUID.randomUUID();
				originalFileName = multipartFile.getOriginalFilename();
				String uploadFileName = uuid.toString() + "_" + originalFileName;
				dBSaveFile = uploadDir + "\\" + uploadFileName;
				log.info(dBSaveFile);
				File saveFile = new File(uploadDir, uploadFileName);
				try {
					//local storage 실제 파일 저장
					multipartFile.transferTo(saveFile);
					log.info("파일업로드 (local save) 성공");
					//강의테이블에 파일 이름, 파일저장경로 저장
					int insertResult = lectureMapper.updateLecPlanFilePath(long_lec_id, originalFileName, dBSaveFile);
					log.info("DB 저장 성공");
					if(insertResult == 1) result = 1;
				} catch (Exception e) {
					log.error(e.getMessage());
				}
			}
		}
		return result;
	}

	@Override
	public Long isExistPlan(Long lec_id) {
		Long lecPlanLecId = lecPlanMapper.isExistPlanLecId(lec_id);
		return lecPlanLecId;
	}


}
