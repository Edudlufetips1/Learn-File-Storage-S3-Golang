package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/bootdotdev/learn-file-storage-s3-golang-starter/internal/auth"
	"github.com/google/uuid"
)

func (cfg *apiConfig) handlerUploadThumbnail(w http.ResponseWriter, r *http.Request) {
	const maxMemory = 10 << 20
	r.ParseMultipartForm(maxMemory)

	file, header, err := r.FormFile("thumbnail")
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Couldn't read thumbnail file", err)
		return
	}
	defer file.Close()

	mediaType := header.Header.Get("Content-Type")

	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Couldn't find JWT", err)
		return
	}

	videoIDString := r.PathValue("videoID")
	videoID, err := uuid.Parse(videoIDString)

	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid ID", err)
		return
	}

	metaData, err := cfg.db.GetVideo(videoID)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "Couldn't retrieve video data", err)
		return
	}

	userID, err := auth.ValidateJWT(token, cfg.jwtSecret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Couldn't validate JWT", err)
		return
	}
	if userID != metaData.UserID {
		respondWithError(w, http.StatusUnauthorized, "Thumbnail does not belong to user", nil)
		return
	}

	fileExtension := strings.Split(mediaType, "/")[1]
	filePath := filepath.Join(cfg.assetsRoot, videoID.String()+"."+fileExtension)
	url := fmt.Sprintf("http://localhost:8091/assets/%s.%s", videoID, fileExtension)
	metaData.ThumbnailURL = &url

	dst, err := os.Create(filePath)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't create destination file", err)
		return
	}
	defer dst.Close()

	_, err = io.Copy(dst, file)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't save thumbnail file", err)
		return
	}

	err = cfg.db.UpdateVideo(metaData)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't update video data", err)
		return
	}
	respondWithJSON(w, http.StatusOK, metaData)
}
