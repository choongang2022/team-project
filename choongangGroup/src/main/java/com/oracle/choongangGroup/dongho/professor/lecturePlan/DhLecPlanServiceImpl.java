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
		int check = 0; // plan table ???????????? ????????? 0, ????????? 1
		String lecPlanFilePath = lectureMapper.findFilePathByLecId(lec_id);
		Long lecPlanLecId = isExistPlan(lec_id);
		System.out.println(lecPlanFilePath);
		System.out.println(lecPlanLecId);
		if (lecPlanLecId == null && lecPlanFilePath == null) {
			log.info("????????? lecPlan, lecPlanFile ??????");
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
				log.info("??????????????? ?????? ??????! ???????????? ?????? : {}", toDelFile);
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
					log.info("??????????????? ?????? ??????! ???????????? ?????? : {}", toDelFile);
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
			URL getPath = this.getClass().getClassLoader().getResource(""); // jasper ????????? ???????????? ?????? ??????
			String sUrl = request.getServletContext().getRealPath("/"); // ????????? ????????? ??????
			
			File file = ResourceUtils.getFile(getPath + "jasperReport/lecPlanPdf.jrxml"); // ????????? ??????
			JasperReport jasperReport = JasperCompileManager.compileReport(file.getAbsolutePath());
			JRBeanCollectionDataSource dataSource = new JRBeanCollectionDataSource(dtoList); // ????????? ?????????
			Map<String, Object> parameters = new HashMap<>(); // ???????????? ?????????(???????????? ????????? ??????)
			ArrayList<?> dataList = (ArrayList<?>) dataSource.getData();
			for (int i = 0; i < dataList.size(); i++) {
				parameters.put(i+ "", dataList.get(i));
			}
			
			JasperPrint jasperPrint = JasperFillManager.fillReport(jasperReport, parameters, dataSource);
			
			fileRealName = "lecPlanPdf_" + System.currentTimeMillis(); // ????????? ????????????
			filePath = sUrl + "pdf/" + fileRealName + ".pdf"; // ?????? ???????????? ?????? ?????? ??????
			
			String uploadDirStr = sUrl + "pdf/";
			File uploadDir = new File(uploadDirStr);
			//???????????? ????????? ??????????????? ???????????? ????????? ??????
			if(!uploadDir.exists()) {
				log.info("uploadFolder??? ???????????? ???????????? ????????????");
				uploadDir.mkdirs();
			}
			//????????? ????????? ??????????????? pdf ?????? ??????
			File[] files = uploadDir.listFiles();
			for (File fileInUpload : files) {
				log.info("?????? ?????? pdf ???????????? : {}", fileInUpload);
				fileInUpload.delete();
			}
			outputStream = new FileOutputStream(new File(filePath)); // ????????? pdf ??????
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
		//?????? ????????? ?????? ??????
		String lecPlanFilePath = lectureMapper.findFilePathByLecId(long_lec_id);
		if(lecPlanFilePath != null) {
			File toDelFile = new File(lecPlanFilePath);
			if(toDelFile.exists()) {
				toDelFile.delete();
				log.info("??????????????? ?????? ??????! ???????????? ?????? : {}", toDelFile);
			}
		}
		// local ???????????? ?????? ?????? ?????? ??? DB??? ????????????,???????????? ??????
		for (MultipartFile multipartFile : multipartFiles) {
			if(!multipartFile.isEmpty()) {
				UUID uuid = UUID.randomUUID();
				originalFileName = multipartFile.getOriginalFilename();
				String uploadFileName = uuid.toString() + "_" + originalFileName;
				dBSaveFile = uploadDir + "\\" + uploadFileName;
				log.info(dBSaveFile);
				File saveFile = new File(uploadDir, uploadFileName);
				try {
					//local storage ?????? ?????? ??????
					multipartFile.transferTo(saveFile);
					log.info("??????????????? (local save) ??????");
					//?????????????????? ?????? ??????, ?????????????????? ??????
					int insertResult = lectureMapper.updateLecPlanFilePath(long_lec_id, originalFileName, dBSaveFile);
					log.info("DB ?????? ??????");
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
